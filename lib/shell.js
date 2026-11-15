// Shell deletion policy.
//
// This is a judgement layer, not a shell: it reads the command text the model
// sent, splits it into simple commands, strips the wrappers that hide a command
// (`sudo`, `env`, `xargs`, `timeout`, ...), and refuses when the command that
// remains is an irreversible delete. It also follows the two payloads that are
// still readable in the text: `bash -c`, `pwsh -Command`, interpreter `-c`, and
// `eval`.
//
// It deliberately does not try to be complete. Script files, downloaded
// binaries and strings assembled at runtime are outside what a text check can
// prove; SECURITY.md says so. The layer stays small enough to audit, and the
// real recoverability promise belongs to `delete_file`.

import { analyzeProgram } from './program.js'

const MAX_CHARS = 64 * 1024

/** Names that delete in a POSIX shell, PowerShell or cmd. */
const DELETION = new Set([
  'rm',
  'rmdir',
  'unlink',
  'shred',
  'srm',
  'del',
  'erase',
  'rd',
  'remove-item',
  'ri',
])

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'pwsh', 'powershell', 'cmd'])

/** Interpreter command-line flags that carry executable source. */
const INTERPRETER_FLAGS = new Map([
  ['python', ['-c']],
  ['python3', ['-c']],
  ['py', ['-c']],
  ['node', ['-e', '--eval', '-p', '--print']],
  ['nodejs', ['-e', '--eval']],
  ['deno', ['eval']],
  ['bun', ['-e', '--eval']],
  ['perl', ['-e', '-E']],
  ['ruby', ['-e']],
  ['php', ['-r']],
  ['lua', ['-e']],
])

const KEYWORDS = new Set([
  '!',
  'if',
  'then',
  'else',
  'elif',
  'fi',
  'do',
  'done',
  'while',
  'until',
  'for',
  'case',
  'esac',
  'select',
  'coproc',
])

/** PowerShell expression operators; a variable followed by one is not a command. */
const POWERSHELL_EXPRESSION = new Set([
  '-eq',
  '-ne',
  '-gt',
  '-ge',
  '-lt',
  '-le',
  '-like',
  '-notlike',
  '-match',
  '-notmatch',
  '-contains',
  '-notcontains',
  '-in',
  '-notin',
  '-is',
  '-isnot',
  '-as',
  '-and',
  '-or',
  '-xor',
  '-not',
  '-band',
  '-bor',
  '-bxor',
  '-shl',
  '-shr',
  '-replace',
  '-split',
  '-join',
  '-f',
  'in',
  '+',
  '-',
  '*',
  '/',
  '%',
  '??',
  '?',
  ':',
  ',',
  '!',
])

const POWERSHELL_LAUNCHERS = new Set(['start-process', 'saps', 'start'])

const WRAPPERS = new Set([
  'sudo',
  'doas',
  'env',
  'command',
  'builtin',
  'exec',
  'nohup',
  'nice',
  'ionice',
  'timeout',
  'stdbuf',
  'setsid',
  'su',
  'runuser',
  'busybox',
  'wsl',
  'chroot',
  'unshare',
  'nsenter',
  'xvfb-run',
  'time',
  'watch',
  'parallel',
  'xargs',
])

/** One refusal code/reason pair. */
function hit(code, reason) {
  return { code, reason }
}

/** Flatten and cap a fragment for a denial message. */
function clip(value, max = 80) {
  const flat = String(value)
    // eslint-disable-next-line no-control-regex -- refusal text must stay one line
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat
}

function commandName(value) {
  let name = String(value).trim().replace(/^\uFEFF/, '')
  if (name.startsWith('&')) name = name.slice(1).trim()
  if (name.startsWith('@')) name = name.slice(1).trim()
  name = name.split(/[\\/]/).pop() ?? name
  return name.toLowerCase().replace(/\.(?:exe|cmd|bat|com)$/, '')
}

function isAssignment(value) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(value)
}

/** `$name = ...`, `$name += ...`, `$name=...` — a PowerShell assignment target. */
function isPowerShellAssignment(words, index) {
  const value = words[index]?.value ?? ''
  if (!/^\$[A-Za-z_][A-Za-z0-9_:]*$/.test(value)) {
    return /^\$[A-Za-z_][A-Za-z0-9_:]*=/.test(value)
  }
  const next = words[index + 1]?.value
  return next === '=' || next === '+=' || next === '-=' || next === '*=' || next === '/='
}

function isHelpFlag(value) {
  return value === '--help' || value === '-h' || value === '-?' || value === '--version' || value === '-V'
}

function isDynamic(value) {
  const trimmed = value.trim()
  return (
    trimmed.startsWith('$') ||
    trimmed.startsWith('%') ||
    trimmed.startsWith('(') ||
    trimmed.startsWith('`') ||
    trimmed.includes('${')
  )
}

/** Skip `-x`, `-x=value` and known value-taking flags; stop at `--`. */
function skipFlags(words, start, withValue = []) {
  let index = start
  while (index < words.length) {
    const value = words[index].value
    if (value === '--') return index + 1
    if (!value.startsWith('-') || value === '-') return index
    const equals = value.indexOf('=')
    if (equals !== -1) {
      index += 1
      continue
    }
    if (withValue.includes(value)) {
      index += 2
      continue
    }
    index += 1
  }
  return index
}

/** An exact flag, or a combined short-flag cluster containing `letter`. */
function flagIndex(words, names, letter) {
  for (let index = 0; index < words.length; index += 1) {
    const value = words[index].value
    if (names.includes(value)) return index
    if (letter !== undefined && /^-[A-Za-z]+$/.test(value) && value.includes(letter)) return index
  }
  return -1
}

/** PowerShell switches are case-insensitive. */
function flagIndexCI(words, names) {
  const lowered = names.map((name) => name.toLowerCase())
  for (let index = 0; index < words.length; index += 1) {
    if (lowered.includes(words[index].value.toLowerCase())) return index
  }
  return -1
}

function hasFlag(words, names) {
  return flagIndex(words, names) !== -1
}

function hasFlagCI(words, names) {
  return flagIndexCI(words, names) !== -1
}

function hasShortFlag(words, letter) {
  return flagIndex(words, [], letter) !== -1
}

/** Interpreter flags, normalizing versioned names such as `python3.11`. */
function interpreterFlags(name) {
  if (INTERPRETER_FLAGS.has(name)) return INTERPRETER_FLAGS.get(name)
  if (/^python\d+(?:\.\d+)*$/.test(name)) return INTERPRETER_FLAGS.get('python')
  return undefined
}

/** Does this command read its program from stdin (rather than a script file)? */
function readsProgramFromStdin(name, args) {
  if (SHELLS.has(name)) {
    if (name === 'cmd') return !hasFlagCI(args, ['/c', '/k'])
    if (name === 'pwsh' || name === 'powershell') {
      return !hasFlagCI(args, ['-command', '-c', '-encodedcommand', '-enc', '-file', '-f'])
    }
    if (hasShortFlag(args, 'c')) return false
    if (args.some((word) => word.value === '-s')) return true
    return !args.some((word) => !word.value.startsWith('-'))
  }
  const flags = interpreterFlags(name)
  if (flags !== undefined) {
    if (hasFlag(args, flags)) return false
    return !args.some((word) => !word.value.startsWith('-'))
  }
  return false
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

function emptySegment(piped, call) {
  return { words: [], piped: piped === true, call: call === true, redirectIn: false, expectRedirect: false }
}

function readAnsiC(text, start) {
  let index = start + 2
  let value = ''
  while (index < text.length) {
    const char = text[index]
    if (char === "'") return { value, end: index + 1 }
    if (char !== '\\') {
      value += char
      index += 1
      continue
    }
    const next = text[index + 1]
    if (next === undefined) break
    switch (next) {
      case 'n': value += '\n'; index += 2; break
      case 't': value += '\t'; index += 2; break
      case 'r': value += '\r'; index += 2; break
      case 'a': value += '\x07'; index += 2; break
      case 'b': value += '\b'; index += 2; break
      case 'f': value += '\f'; index += 2; break
      case 'v': value += '\v'; index += 2; break
      case 'e': value += '\x1b'; index += 2; break
      case '\\': value += '\\'; index += 2; break
      case "'": value += "'"; index += 2; break
      case '"': value += '"'; index += 2; break
      case 'x': {
        const match = /^[0-9A-Fa-f]{1,2}/.exec(text.slice(index + 2))
        if (match === null) return null
        value += String.fromCharCode(Number.parseInt(match[0], 16))
        index += 2 + match[0].length
        break
      }
      default: {
        if (/[0-7]/.test(next)) {
          const match = /^[0-7]{1,3}/.exec(text.slice(index + 1))
          value += String.fromCharCode(Number.parseInt(match[0], 8))
          index += 1 + match[0].length
        } else {
          value += next
          index += 2
        }
      }
    }
  }
  return null
}

function skipHeredoc(text, start, stripTabs) {
  let index = start
  while (text[index] === ' ' || text[index] === '\t') index += 1
  const quote = text[index] === "'" || text[index] === '"' ? text[index] : ''
  let delimiter = ''
  if (quote !== '') {
    index += 1
    while (index < text.length && text[index] !== quote) {
      delimiter += text[index]
      index += 1
    }
    if (text[index] !== quote) return -1
    index += 1
  } else {
    while (index < text.length && !/[\s;|&<>]/.test(text[index])) {
      delimiter += text[index]
      index += 1
    }
  }
  if (delimiter === '') return -1

  let lineEnd = text.indexOf('\n', index)
  if (lineEnd === -1) return -1
  let cursor = lineEnd + 1
  while (cursor <= text.length) {
    let end = text.indexOf('\n', cursor)
    if (end === -1) end = text.length
    let line = text.slice(cursor, end)
    if (stripTabs) line = line.replace(/^\t+/, '')
    if (line.trimEnd() === delimiter) return end < text.length ? end + 1 : text.length
    if (end === text.length) return -1
    cursor = end + 1
  }
  return -1
}

function lex(text, dialect) {
  const segments = []
  let current = emptySegment(false)
  let pendingPipe = false
  let word = ''
  let inWord = false
  let wordQuoted = false
  let state = 'normal'
  const substitutions = []
  const backticks = []
  let index = 0

  const pushWord = () => {
    if (!inWord) return
    current.words.push({ value: word, quoted: wordQuoted, redirect: current.expectRedirect === true })
    current.expectRedirect = false
    word = ''
    inWord = false
    wordQuoted = false
  }
  const finishSegment = (pipeNext = false, callNext = false) => {
    pushWord()
    if (current.words.length > 0) segments.push(current)
    pendingPipe = pipeNext
    current = emptySegment(pendingPipe, callNext)
  }

  while (index < text.length) {
    const char = text[index]
    const next = text[index + 1]

    if (state === 'single') {
      if (char === "'") state = 'normal'
      else word += char
      index += 1
      continue
    }

    if (state === 'double') {
      if (char === '"') {
        state = 'normal'
        index += 1
        continue
      }
      if (char === '\\' && dialect === 'posix') {
        if (next === '"' || next === '\\' || next === '$' || next === '`') {
          word += next
          index += 2
        } else {
          word += char
          index += 1
        }
        continue
      }
      if (dialect === 'pwsh' && char === '`') {
        if (next !== undefined) word += next
        index += 2
        continue
      }
      if (dialect !== 'cmd' && char === '$' && next === '(') {
        pushWord()
        finishSegment(false)
        substitutions.push({ returnState: state, depth: 1 })
        state = 'normal'
        index += 2
        continue
      }
      if (dialect === 'posix' && char === '`') {
        pushWord()
        finishSegment(false)
        if (backticks.length === 0) {
          backticks.push(state)
          state = 'normal'
        } else {
          state = backticks.pop()
        }
        index += 1
        continue
      }
      word += char
      index += 1
      continue
    }

    // normal state
    if (char === "'") {
      state = 'single'
      inWord = true
      wordQuoted = true
      index += 1
      continue
    }
    if (char === '"') {
      state = 'double'
      inWord = true
      wordQuoted = true
      index += 1
      continue
    }
    if (char === '$' && next === "'") {
      const decoded = readAnsiC(text, index)
      if (decoded === null) return { error: 'an ANSI-C quoted string is unterminated or malformed' }
      word += decoded.value
      inWord = true
      wordQuoted = true
      index = decoded.end
      continue
    }
    if (dialect !== 'cmd' && char === '$' && next === '(') {
      pushWord()
      finishSegment(false)
      substitutions.push({ returnState: state, depth: 1 })
      index += 2
      continue
    }
    if (dialect === 'posix' && char === '`') {
      pushWord()
      finishSegment(false)
      if (backticks.length === 0) {
        backticks.push(state)
        state = 'normal'
      } else {
        state = backticks.pop()
      }
      index += 1
      continue
    }
    if (char === '\\' && dialect === 'posix') {
      if (next === '\n') {
        index += 2
        continue
      }
      if (next === undefined) {
        word += char
        index += 1
        continue
      }
      word += next
      inWord = true
      wordQuoted = true
      index += 2
      continue
    }
    if (dialect === 'pwsh' && char === '`') {
      if (next !== undefined) word += next
      inWord = inWord || next !== undefined
      wordQuoted = true
      index += 2
      continue
    }
    if (char === ' ' || char === '\t' || char === '\r') {
      pushWord()
      index += 1
      continue
    }
    if (char === '\n') {
      finishSegment(false)
      index += 1
      continue
    }
    if (char === '#') {
      const atBoundary = !inWord && (index === 0 || /[\s;&|(){}]/.test(text[index - 1]))
      if (atBoundary) {
        const newline = text.indexOf('\n', index)
        index = newline === -1 ? text.length : newline
        continue
      }
    }
    if (char === ';') {
      finishSegment(false)
      index += 1
      continue
    }
    if (char === '|') {
      if (next === '|') {
        finishSegment(false)
        index += 2
      } else {
        finishSegment(true)
        index += 1
      }
      continue
    }
    if (char === '&') {
      if (next === '&') finishSegment(false, false)
      else if (dialect === 'pwsh') finishSegment(false, true)
      else finishSegment(false, false)
      index += next === '&' ? 2 : 1
      continue
    }
    if (char === '(' ) {
      finishSegment(false)
      if (substitutions.length > 0) substitutions[substitutions.length - 1].depth += 1
      index += 1
      continue
    }
    if (char === ')') {
      finishSegment(false)
      if (substitutions.length > 0) {
        const top = substitutions[substitutions.length - 1]
        if (top.depth > 1) top.depth -= 1
        else {
          substitutions.pop()
          state = top.returnState
        }
      }
      index += 1
      continue
    }
    if (char === '{' || char === '}') {
      finishSegment(false)
      index += 1
      continue
    }
    if (char === '<') {
      if (text.startsWith('<<<', index)) {
        current.redirectIn = true
        current.expectRedirect = true
        index += 3
        continue
      }
      if (dialect !== 'pwsh' && dialect !== 'cmd' && text.startsWith('<<', index)) {
        pushWord()
        current.redirectIn = true
        const stripTabs = text[index + 2] === '-'
        const end = skipHeredoc(text, index + 2 + (stripTabs ? 1 : 0), stripTabs)
        if (end === -1) return { error: 'a here-document is unterminated' }
        index = end
        continue
      }
      if (next === '(') {
        index += 1
        continue
      }
      current.redirectIn = true
      current.expectRedirect = true
      index += 1
      if (text[index] === '&') index += 1
      continue
    }
    if (char === '>') {
      current.expectRedirect = true
      index += 1
      if (text[index] === '>') index += 1
      if (text[index] === '&') index += 1
      continue
    }

    word += char
    inWord = true
    index += 1
  }

  pushWord()
  if (current.words.length > 0) segments.push(current)
  if (state !== 'normal' || substitutions.length > 0 || backticks.length > 0) {
    return { error: 'a quote or command substitution is unterminated' }
  }
  return { segments }
}

// ---------------------------------------------------------------------------
// Segment analysis
// ---------------------------------------------------------------------------

/** Strip a wrapper and return the index of the command it wraps. */
function afterWrapper(name, words, at, dialect, depth) {
  switch (name) {
    case 'sudo':
      return skipFlags(words, at + 1, ['-u', '-g', '-p', '-C', '-T', '-U', '-R', '-D', '-t'])
    case 'doas':
      return skipFlags(words, at + 1, ['-u', '-C'])
    case 'env': {
      // env -S / --split-string carries a command string, not a flag value.
      // Analyzing it is the only way to see `env -S 'rm -rf build'`.
      let next = at + 1
      while (next < words.length) {
        const value = words[next].value
        if (value === '-S' || value === '--split-string') {
          const payload = words[next + 1]
          if (payload === undefined || payload.value === '') {
            return hit('SHELL_UNINSPECTABLE', `${name} -S has no command text`)
          }
          if (isDynamic(payload.value)) {
            return hit('SHELL_UNINSPECTABLE', `the ${name} -S payload is built at runtime`)
          }
          return analyzeText(payload.value, dialect, depth + 1) ?? 'allow'
        }
        if (value.startsWith('--split-string=')) {
          const payload = value.slice('--split-string='.length)
          if (payload === '') return hit('SHELL_UNINSPECTABLE', `${name} --split-string has no command text`)
          if (isDynamic(payload)) return hit('SHELL_UNINSPECTABLE', `the ${name} --split-string payload is built at runtime`)
          return analyzeText(payload, dialect, depth + 1) ?? 'allow'
        }
        if (value === '--') { next += 1; break }
        if (value.startsWith('-')) {
          next += value === '-u' || value === '--unset' || value === '-C' || value === '--chdir' ? 2 : 1
          continue
        }
        if (isAssignment(value)) { next += 1; continue }
        break
      }
      return next
    }
    case 'command': {
      const flags = words.slice(at + 1)
      if (hasFlag(flags, ['-v', '-V'])) return 'query'
      return skipFlags(words, at + 1)
    }
    case 'builtin':
    case 'nohup':
    case '!':
      return at + 1
    case 'exec':
      return skipFlags(words, at + 1, ['-a'])
    case 'nice':
      return skipFlags(words, at + 1, ['-n'])
    case 'ionice':
      return skipFlags(words, at + 1, ['-c', '-n', '-p'])
    case 'timeout':
      return skipFlags(words, at + 1, ['-s', '--signal', '-k', '--kill-after']) + 1
    case 'stdbuf':
      return skipFlags(words, at + 1)
    case 'setsid':
      return skipFlags(words, at + 1)
    case 'busybox':
      return at + 1
    case 'wsl':
      return skipFlags(words, at + 1, ['-d', '--distribution', '-u', '--user', '--cd', '--shell-type'])
    case 'chroot':
      return skipFlags(words, at + 1) + 1
    case 'unshare':
    case 'nsenter':
      return skipFlags(words, at + 1, ['-t', '--target', '-S', '-G', '-R', '--root', '-w', '--wd'])
    case 'xvfb-run':
      return skipFlags(words, at + 1, ['-s', '-f', '-n', '-p'])
    case 'time':
      return skipFlags(words, at + 1)
    case 'xargs':
      return skipFlags(words, at + 1, ['-I', '-n', '-P', '-L', '-s', '-a', '-E', '-d', '-e'])
    case 'su':
    case 'runuser': {
      const command = words.slice(at + 1)
      const index = flagIndex(command, ['-c', '--command'])
      if (index === -1) return 'allow'
      const payload = command[index + 1]
      if (payload === undefined || payload.value === '') {
        return hit('SHELL_UNINSPECTABLE', `\`${name} -c\` has no command text`)
      }
      if (isDynamic(payload.value)) {
        return hit('SHELL_UNINSPECTABLE', `the \`${name} -c\` payload is built at runtime`)
      }
      return analyzeText(payload.value, dialect, depth + 1) ?? 'allow'
    }
    case 'watch':
    case 'parallel': {
      const next = skipFlags(words, at + 1, ['-n', '--interval', '-d', '--differences', '-j', '--jobs'])
      const payload = words[next]
      if (payload === undefined) return 'allow'
      if (wordQuotedOrSpaced(payload)) {
        if (isDynamic(payload.value)) {
          return hit('SHELL_UNINSPECTABLE', `the \`${name}\` command is built at runtime`)
        }
        return analyzeText(payload.value, dialect, depth + 1) ?? 'allow'
      }
      return next
    }
    default:
      return at + 1
  }
}

function wordQuotedOrSpaced(word) {
  return word.quoted === true || /\s/.test(word.value)
}

/** Follow a PowerShell process launcher into the command it starts. */
function analyzeLauncher(name, args, depth) {
  const index = args.findIndex((word) => !word.value.startsWith('-') && word.value !== '')
  if (index === -1) return null
  const executable = commandName(args[index].value)
  const interpreter = interpreterFlags(executable)
  const isShell = SHELLS.has(executable) || executable === 'wsl'
  if (!isShell && interpreter === undefined) return null

  const rest = args.slice(index)
  if (isShell) {
    // Prefer the explicit -Command / -c / /c payload: it preserves the quoting
    // of a pipeline that the joined text would lose.
    const normalized = rest.map((word) => ({ ...word, value: word.value.replace(/,$/, '') }))
    const shellFlags =
      executable === 'cmd' ? ['/c', '/k'] : executable === 'pwsh' || executable === 'powershell' ? ['-command', '-c'] : ['-c']
    const flag = flagIndexCI(normalized, shellFlags)
    if (flag !== -1) {
      const payload = rest[flag + 1]
      if (payload === undefined || payload.value === '') {
        return hit('SHELL_UNINSPECTABLE', 'the launcher has no command text')
      }
      if (isDynamic(payload.value)) {
        return hit('SHELL_UNINSPECTABLE', 'the launcher command is built at runtime')
      }
      const dialect = executable === 'pwsh' || executable === 'powershell' ? 'pwsh' : executable === 'cmd' ? 'cmd' : 'posix'
      return analyzeText(payload.value, dialect, depth + 1)
    }
  }

  const nested = rest.map((word) => word.value).join(' ').replace(/,/g, ' ')
  if (nested !== '') {
    const dialect = executable === 'pwsh' || executable === 'powershell' ? 'pwsh' : executable === 'cmd' ? 'cmd' : 'posix'
    const result = analyzeText(nested, dialect, depth + 1)
    if (result !== null) return result
  }

  if (interpreter !== undefined) {
    const rest = args.slice(index)
    const flag = flagIndex(rest, interpreter)
    if (flag !== -1) {
      const payload = rest[flag + 1]
      if (payload === undefined || payload.value === '') {
        return hit('SHELL_UNINSPECTABLE', '`' + name + ' ' + executable + '` has no inline program text')
      }
      if (isDynamic(payload.value)) {
        return hit('SHELL_UNINSPECTABLE', 'the `' + name + ' ' + executable + '` program text is built at runtime')
      }
      const specialized = interpreterDeletion(executable, payload.value)
      if (specialized !== null) return specialized
      const result = analyzeProgram(payload.value)
      if (result !== null) return result
    }
  }
  return null
}

/** Does the word at `words[index]` start a deletion command? */
function deletionHit(name, args) {
  if (DELETION.has(name)) {
    if (args.length > 0 && args.every((word) => isHelpFlag(word.value))) return null
    const shown = clip([name, ...args.map((word) => word.value)].join(' '))
    return hit('SHELL_DELETE', `the command deletes with \`${shown}\``)
  }

  if (name === 'find') {
    for (let index = 0; index < args.length; index += 1) {
      const value = args[index].value
      if (value === '-delete') return hit('SHELL_DELETE', '`find -delete` removes every path it matches')
      if (value === '-exec' || value === '-execdir' || value === '-ok' || value === '-okdir') {
        const next = args[index + 1]
        if (next !== undefined && DELETION.has(commandName(next.value))) {
          return hit('SHELL_DELETE', `\`find ${value} ${next.value}\` deletes every path it matches`)
        }
        if (
          next !== undefined &&
          (SHELLS.has(commandName(next.value)) || interpreterFlags(commandName(next.value)) !== undefined)
        ) {
          return hit(
            'SHELL_UNINSPECTABLE',
            `\`find ${value} ${next.value} ...\` runs a shell whose payload cannot be bounded`,
          )
        }
      }
    }
    return null
  }

  if (name === 'git') {
    const subcommand = args[0]?.value
    if (subcommand === 'clean' && args.slice(1).some((word) => /^-[A-Za-z]*f/.test(word.value) || word.value === '--force')) {
      return hit('SHELL_DELETE', '`git clean -f` permanently removes untracked files')
    }
    if (subcommand === 'rm' && !args.slice(1).some((word) => word.value === '--cached')) {
      return hit('SHELL_DELETE', '`git rm` removes files from the working tree')
    }
    return null
  }

  if (name === 'rsync') {
    const destructive = args.find(
      (word) =>
        word.value.startsWith('--delete') ||
        word.value === '--del' ||
        word.value === '--remove-source-files',
    )
    return destructive === undefined ? null : hit('SHELL_DELETE', `\`rsync ${destructive.value}\` deletes files`)
  }

  if (name === 'robocopy') {
    const destructive = args.find((word) => /^\/(?:mir|purge)$/i.test(word.value))
    return destructive === undefined ? null : hit('SHELL_DELETE', `\`robocopy ${destructive.value}\` mirrors or purges the destination`)
  }

  return null
}

function analyzeSegment(segment, dialect, depth) {
  let words = segment.words.filter((word) => word.redirect !== true)
  if (words.length === 0) return null

  let start = 0
  while (start < words.length && isAssignment(words[start].value)) start += 1
  if (start >= words.length) return null
  words = words.slice(start)

  let index = 0
  while (index < words.length && isPowerShellAssignment(words, index)) index += 2
  if (index >= words.length) return null
  words = words.slice(index)

  index = 0
  let steps = 0
  while (index < words.length && steps < 12) {
    steps += 1
    const name = commandName(words[index].value)
    if (KEYWORDS.has(name)) {
      index += 1
      continue
    }
    if (name === 'function') return null
    if (!WRAPPERS.has(name)) break

    const result = afterWrapper(name, words, index, dialect, depth)
    if (result === 'query') return null
    if (result === 'allow') return null
    if (typeof result === 'number') {
      index = result
      continue
    }
    return result
  }

  if (index >= words.length) return null
  words = words.slice(index)
  const name = commandName(words[0].value)
  const args = words.slice(1)
  if (name === '') return null

  // In PowerShell a quoted string at statement position is an expression, not
  // a command; executing it requires the call operator, which marks the
  // segment. `$x = 'rm'` and `@('rm')` must not be refused.
  if (dialect === 'pwsh' && words[0].quoted === true && segment.call !== true) return null

  if (dialect === 'pwsh' && POWERSHELL_LAUNCHERS.has(name)) {
    const nested = analyzeLauncher(name, args, depth)
    if (nested !== null) return nested
  }

  if (/^\[(?:system\.)?io\.(?:file|directory)\]::delete(?:directory)?$/.test(name)) {
    return hit('SHELL_DELETE', `the command deletes with \`${clip(words[0].value)}\``)
  }

  if (/^[$%]/.test(words[0].value.trim()) || words[0].value.trim().startsWith('${')) {
    // In PowerShell a bare variable is an expression (`$out | Select-String`,
    // `$x -eq 1`, `$a in $b`), not a command; with command-like operands it
    // invokes the command in the variable. POSIX and cmd expand the variable
    // into a command either way.
    if (dialect === 'pwsh' && args.length === 0) return null
    if (dialect === 'pwsh' && segment.call !== true && args.some((word) => POWERSHELL_EXPRESSION.has(word.value.toLowerCase()))) {
      return null
    }
    return hit('SHELL_UNINSPECTABLE', `the command name \`${clip(words[0].value)}\` is built at runtime`)
  }

  if ((segment.piped || segment.redirectIn) && readsProgramFromStdin(name, args)) {
    return hit(
      'SHELL_UNINSPECTABLE',
      `\`${name}\` reads its program from stdin, so its contents cannot be inspected`,
    )
  }

  if (SHELLS.has(name)) {
    if (name === 'cmd') {
      const cmdIndex = flagIndexCI(args, ['/c', '/k'])
      if (cmdIndex === -1) return null
      const payload = args[cmdIndex + 1]
      if (payload === undefined || payload.value === '') {
        return hit('SHELL_UNINSPECTABLE', '`cmd /c` has no command text')
      }
      if (isDynamic(payload.value)) return hit('SHELL_UNINSPECTABLE', 'the `cmd /c` payload is built at runtime')
      return analyzeText(payload.value, 'cmd', depth + 1)
    }

    if (name === 'pwsh' || name === 'powershell') {
      const encoded = flagIndexCI(args, ['-encodedcommand', '-enc'])
      if (encoded !== -1) {
        const value = args[encoded + 1]?.value
        const decoded = decodePowerShell(value)
        if (decoded === null) {
          return hit('SHELL_UNINSPECTABLE', 'its `-EncodedCommand` payload could not be decoded')
        }
        return analyzeText(decoded, 'pwsh', depth + 1)
      }
      const command = flagIndexCI(args, ['-command', '-c'])
      if (command !== -1) {
        const payload = args[command + 1]
        if (payload === undefined || payload.value === '') {
          return hit('SHELL_UNINSPECTABLE', '`-Command` has no command text')
        }
        if (isDynamic(payload.value)) return hit('SHELL_UNINSPECTABLE', 'the `-Command` payload is built at runtime')
        return analyzeText(payload.value, 'pwsh', depth + 1)
      }
      return null
    }

    const command = flagIndex(args, ['-c'], 'c')
    if (command !== -1) {
      const payload = args[command + 1]
      if (payload === undefined || payload.value === '') {
        return hit('SHELL_UNINSPECTABLE', '`-c` has no command text')
      }
      if (isDynamic(payload.value)) return hit('SHELL_UNINSPECTABLE', 'the `-c` payload is built at runtime')
      return analyzeText(payload.value, 'posix', depth + 1)
    }
    return null
  }

  const interpreter = interpreterFlags(name)
  if (interpreter !== undefined) {
    const flag = flagIndex(args, interpreter)
    if (flag === -1) return null
    const payload = args[flag + 1]
    if (payload === undefined || payload.value === '') {
      return hit('SHELL_UNINSPECTABLE', `\`${name}\` has no inline program text`)
    }
    if (isDynamic(payload.value)) return hit('SHELL_UNINSPECTABLE', `the \`${name}\` program text is built at runtime`)
    const specialized = interpreterDeletion(name, payload.value)
    if (specialized !== null) return specialized
    const result = analyzeProgram(payload.value)
    if (result !== null) return result
    return null
  }

  if (name === 'eval' || name === 'iex' || name === 'invoke-expression') {
    const payload = args[0]
    if (payload === undefined) {
      if (segment.piped || segment.redirectIn) {
        return hit('SHELL_UNINSPECTABLE', `\`${name}\` reads its program from stdin, so its contents cannot be inspected`)
      }
      return null
    }
    if (isDynamic(payload.value)) {
      return hit('SHELL_UNINSPECTABLE', `the \`${name}\` payload is built at runtime`)
    }
    return analyzeText(payload.value, name === 'eval' ? 'posix' : 'pwsh', depth + 1)
  }

  return deletionHit(name, args)
}

function decodePowerShell(value) {
  if (typeof value !== 'string') return null
  const compact = value.trim()
  if (compact === '' || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null
  try {
    const decoded = Buffer.from(compact, 'base64').toString('utf16le')
    // A decoded command is text; NULs or control bytes mean this was not UTF-16.
    if (decoded.length === 0 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(decoded)) return null
    return decoded
  } catch {
    return null
  }
}

/** Interpreter-specific spellings that do not use a JS-style call. */
function interpreterDeletion(name, code) {
  if (/^python\d*(?:\.\d+)*$/.test(name)) {
    const imports = /\bfrom\s+(?:os|shutil)\s+import\b[^;\n]*\b(?:remove|unlink|rmdir|rmtree)\b/.test(code)
    const calls = /\b(?:remove|unlink|rmdir|rmtree)\s*\(/.test(code)
    if (imports && calls) {
      return hit('SHELL_DELETE', 'the Python program imports and calls a deletion helper')
    }
    if (/\b(?:os|shutil)\s*\.\s*(?:remove|unlink|rmdir|rmtree)\s*\(/.test(code)) {
      return hit('SHELL_DELETE', 'the Python program removes files')
    }
  }
  if (name === 'perl' && /\bunlink\b/.test(code)) {
    return hit('SHELL_DELETE', 'the Perl program calls `unlink`, which deletes a file')
  }
  if (name === 'ruby' && /\b(?:FileUtils\s*\.\s*rm_rf|File\s*\.\s*delete|Dir\s*\.\s*rmdir|rm_rf)\b/.test(code)) {
    return hit('SHELL_DELETE', 'the Ruby program removes files')
  }
  return null
}

/**
 * Analyze one shell payload.
 * @param {string} text
 * @param {{ dialect?: 'posix' | 'pwsh' | 'cmd' }} [options]
 * @returns {{ code: string, reason: string } | null}
 */
export function analyzeShell(text, options = {}) {
  return analyzeText(text, options.dialect ?? 'posix', 0)
}

function analyzeText(text, dialect, depth) {
  if (typeof text !== 'string' || text.trim() === '') return null
  if (text.length > MAX_CHARS) {
    return hit(
      'SHELL_TOO_LONG',
      `the command is longer than ${MAX_CHARS} characters, so it could not be inspected`,
    )
  }
  if (depth > 3) return hit('SHELL_TOO_DEEP', 'the shell payload is nested more than 3 levels deep')

  const lexed = lex(text, dialect)
  if (lexed.error !== undefined) return hit('SHELL_UNINSPECTABLE', lexed.error)
  for (const segment of lexed.segments) {
    const result = analyzeSegment(segment, dialect, depth)
    if (result !== null) return result
  }
  return null
}
