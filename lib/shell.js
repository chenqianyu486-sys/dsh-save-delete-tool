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

/** Decode cmd.exe caret escapes in a command name (d^el -> del). */
function decodeCmdCarets(value) {
  let result = ''
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === '^' && index + 1 < value.length) {
      index += 1
      result += value[index]
    } else {
      result += value[index]
    }
  }
  return result
}

function cmdCommandName(rawValue) {
  const trimmed = decodeCmdCarets(String(rawValue).trim().replace(/^\uFEFF/, '').replace(/^@/, ''))
  if (trimmed.includes('/') && !trimmed.includes('\\')) {
    const head = trimmed.split('/')[0].toLowerCase().replace(/\.(?:exe|cmd|bat|com)$/, '')
    if (DELETION.has(head) || SHELLS.has(head)) return head
  }
  return decodeCmdCarets(commandName(rawValue))
}

const CMD_IF_UNARY = new Set(['exist', 'defined', 'errorlevel', 'cmdextversion'])
const CMD_IF_CMP = new Set(['equ', 'neq', 'lss', 'leq', 'gtr', 'geq', '=='])

function skipCmdIfHeader(words, start) {
  let index = start
  if (index < words.length && words[index].value.toLowerCase() === '/i') index += 1
  if (index < words.length && words[index].value.toLowerCase() === 'not') index += 1
  if (index >= words.length) return index
  const head = words[index].value.toLowerCase()
  if (CMD_IF_UNARY.has(head)) {
    return Math.min(words.length, index + 2)
  }
  if (words[index].value.includes('==')) {
    return index + 1
  }
  if (index + 2 < words.length && CMD_IF_CMP.has(words[index + 1].value.toLowerCase())) {
    return index + 3
  }
  return index
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

const WRAPPER_VALUE_FLAGS = new Map([
  [
    'sudo',
    [
      '-u', '--user', '-g', '--group', '-p', '--prompt', '-C', '--close-from',
      '-T', '--command-timeout', '-U', '--other-user', '-R', '--chroot',
      '-D', '--chdir', '-t', '--type', '-r', '--role', '-h', '--host',
    ],
  ],
  ['doas', ['-u', '--user', '-C', '--config']],
  ['env', ['-u', '--unset', '-C', '--chdir', '-S', '--split-string']],
  ['exec', ['-a']],
  ['nice', ['-n', '--adjustment']],
  ['ionice', ['-c', '--class', '-n', '--classdata', '-p', '--pid', '-u', '--uid']],
  ['timeout', ['-s', '--signal', '-k', '--kill-after']],
  ['stdbuf', ['-i', '--input', '-o', '--output', '-e', '--error']],
  ['wsl', ['-d', '--distribution', '-u', '--user', '--cd', '--shell-type']],
  [
    'unshare',
    [
      '--propagation', '--setgroups', '--map-user', '--map-group', '--map-users', '--map-groups',
      '--root', '--wd',
    ],
  ],
  ['nsenter', ['-t', '--target', '-S', '--setuid', '-G', '--setgid', '-R', '--root', '-w', '--wd']],
  ['xvfb-run', ['-s', '-f', '-n', '-p']],
  [
    'xargs',
    [
      '-I', '-n', '--max-args', '-P', '--max-procs', '-L',
      '-s', '--max-chars', '-a', '--arg-file', '-E', '-d', '--delimiter',
      '--process-slot-var',
    ],
  ],
  ['runuser', ['-u', '--user', '-g', '--group', '-G', '--supp-group', '-s', '--shell', '-c', '--command', '--session-command']],
  ['su', ['-c', '--command', '--session-command']],
  ['watch', ['-n', '--interval', '-d', '--differences']],
  [
    'parallel',
    [
      '-j', '--jobs', '-S', '--sshlogin', '--delay', '--joblog', '--results',
      '--sshloginfile', '--workdir', '--tmpdir', '--env', '--timeout', '--retries',
      '--load', '--memfree', '--arg-file', '--colsep',
    ],
  ],
])

function wrapperCommandIndex(words) {
  let index = 0
  while (index < words.length) {
    if (isAssignment(words[index].value)) {
      index += 1
      continue
    }
    const name = commandName(words[index].value)
    if (KEYWORDS.has(name)) {
      index += 1
      continue
    }
    if (!WRAPPERS.has(name)) break
    const next = skipFlags(words, index + 1, WRAPPER_VALUE_FLAGS.get(name) ?? [])
    if (name === 'env') {
      index = next
      while (index < words.length && isAssignment(words[index].value)) index += 1
      continue
    }
    if (name === 'timeout' || name === 'chroot') {
      index = next + 1
      continue
    }
    index = next
  }
  return index
}

function lex(text, dialect) {
  const segments = []
  let current = emptySegment(false)
  let pendingPipe = false
  let word = ''
  let inWord = false
  let wordQuoted = false
  let wordStartsQuoted = false
  let state = 'normal'
  const substitutions = []
  const backticks = []
  let commandSubstitution = false
  let index = 0

  const substitutionIsCommand = () => {
    // A substitution inside an assignment value is data until the assignment
    // is later used as a command. Otherwise a substitution before the command
    // word, or after only keywords/wrappers (or find -exec), can become the executed command.
    if (inWord && /^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) return false
    if (current.words.length === 0) return true
    const lastValue = current.words[current.words.length - 1]?.value
    if (lastValue === '-exec' || lastValue === '-execdir' || lastValue === '-ok' || lastValue === '-okdir') {
      return true
    }
    if (current.words.every((entry) => {
      const name = commandName(entry.value)
      return isAssignment(entry.value) || KEYWORDS.has(name) || WRAPPERS.has(name)
    })) {
      return true
    }
    return wrapperCommandIndex(current.words) >= current.words.length
  }

  const pushWord = () => {
    if (!inWord) return
    current.words.push({
      value: word,
      quoted: wordQuoted,
      startsQuoted: wordStartsQuoted,
      redirect: current.expectRedirect === true,
    })
    current.expectRedirect = false
    word = ''
    inWord = false
    wordQuoted = false
    wordStartsQuoted = false
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
        if (substitutionIsCommand()) commandSubstitution = true
        pushWord()
        finishSegment(false)
        substitutions.push({ returnState: state, depth: 1 })
        state = 'normal'
        index += 2
        continue
      }
      if (dialect === 'posix' && char === '`') {
        if (substitutionIsCommand()) commandSubstitution = true
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
      if (!inWord) wordStartsQuoted = true
      state = 'single'
      inWord = true
      wordQuoted = true
      index += 1
      continue
    }
    if (char === '"') {
      if (!inWord) wordStartsQuoted = true
      state = 'double'
      inWord = true
      wordQuoted = true
      index += 1
      continue
    }
    if (char === '$' && next === "'") {
      if (!inWord) wordStartsQuoted = true
      const decoded = readAnsiC(text, index)
      if (decoded === null) return { error: 'an ANSI-C quoted string is unterminated or malformed' }
      word += decoded.value
      inWord = true
      wordQuoted = true
      index = decoded.end
      continue
    }
    if (dialect !== 'cmd' && char === '$' && next === '(') {
      if (substitutionIsCommand()) commandSubstitution = true
      pushWord()
      finishSegment(false)
      substitutions.push({ returnState: state, depth: 1 })
      index += 2
      continue
    }
    if (dialect === 'posix' && char === '`') {
      if (substitutionIsCommand()) commandSubstitution = true
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
        // A process substitution can feed a script to bash/python. Mark it as
        // an input the parser cannot inspect instead of dropping it.
        current.redirectIn = true
        current.expectRedirect = true
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
  return { segments, commandSubstitution }
}

// ---------------------------------------------------------------------------
// Segment analysis
// ---------------------------------------------------------------------------

/** Strip a wrapper and return the index of the command it wraps. */
function afterWrapper(name, words, at, dialect, depth) {
  switch (name) {
    case 'sudo':
      return skipFlags(words, at + 1, [
        '-u', '--user', '-g', '--group', '-p', '--prompt', '-C', '--close-from',
        '-T', '--command-timeout', '-U', '--other-user', '-R', '--chroot',
        '-D', '--chdir', '-t', '--type', '-r', '--role', '-h', '--host',
      ])
    case 'doas':
      return skipFlags(words, at + 1, ['-u', '--user', '-C', '--config'])
    case 'env': {
      // env -S / --split-string carries a command string, not a flag value.
      // Analyzing it is the only way to see `env -S 'rm -rf build'` or `env -iS ...`.
      let next = at + 1
      while (next < words.length) {
        const value = words[next].value
        if (value === '--') { next += 1; break }
        if (value === '-u' || value === '--unset' || value === '-C' || value === '--chdir') {
          next += 2
          continue
        }
        if (value === '--split-string') {
          const payload = words[next + 1]
          if (payload === undefined || payload.value === '') {
            return hit('SHELL_UNINSPECTABLE', `${name} --split-string has no command text`)
          }
          if (isDynamic(payload.value)) {
            return hit('SHELL_UNINSPECTABLE', `the ${name} --split-string payload is built at runtime`)
          }
          return analyzeText(payload.value, dialect, depth + 1) ?? 'allow'
        }
        if (value.startsWith('--split-string=')) {
          const payload = value.slice('--split-string='.length)
          if (payload === '') return hit('SHELL_UNINSPECTABLE', `${name} --split-string has no command text`)
          if (isDynamic(payload)) return hit('SHELL_UNINSPECTABLE', `the ${name} --split-string payload is built at runtime`)
          return analyzeText(payload, dialect, depth + 1) ?? 'allow'
        }
        const splitMatch = /^-[A-Za-z]*S(.*)$/s.exec(value)
        if (splitMatch !== null) {
          const payload = splitMatch[1] !== '' ? splitMatch[1] : words[next + 1]?.value
          if (payload === undefined || payload === '') {
            return hit('SHELL_UNINSPECTABLE', `${name} -S has no command text`)
          }
          if (isDynamic(payload)) {
            return hit('SHELL_UNINSPECTABLE', `the ${name} -S payload is built at runtime`)
          }
          return analyzeText(payload, dialect, depth + 1) ?? 'allow'
        }
        if (value.startsWith('-')) {
          next += 1
          continue
        }
        if (isAssignment(value)) { next += 1; continue }
        break
      }
      return next
    }
    case 'command': {
      let next = at + 1
      while (next < words.length) {
        const value = words[next].value
        if (value === '--') {
          next += 1
          break
        }
        if (!value.startsWith('-') || value === '-') break
        if (value === '-v' || value === '-V' || /^-[A-Za-z]*[vV][A-Za-z]*$/.test(value)) {
          return 'query'
        }
        next += 1
      }
      return next
    }
    case 'builtin':
    case '!':
      return at + 1
    case 'nohup':
      return skipFlags(words, at + 1)
    case 'exec':
      return skipFlags(words, at + 1, ['-a'])
    case 'nice':
      return skipFlags(words, at + 1, ['-n', '--adjustment'])
    case 'ionice':
      return skipFlags(words, at + 1, ['-c', '--class', '-n', '--classdata', '-p', '--pid', '-u', '--uid'])
    case 'timeout':
      return skipFlags(words, at + 1, ['-s', '--signal', '-k', '--kill-after']) + 1
    case 'stdbuf':
      return skipFlags(words, at + 1, ['-i', '--input', '-o', '--output', '-e', '--error'])
    case 'setsid':
      return skipFlags(words, at + 1)
    case 'busybox':
      return skipFlags(words, at + 1)
    case 'wsl':
      return skipFlags(words, at + 1, ['-d', '--distribution', '-u', '--user', '--cd', '--shell-type'])
    case 'chroot':
      return skipFlags(words, at + 1) + 1
    case 'unshare':
      return skipFlags(words, at + 1, [
        '--propagation', '--setgroups', '--map-user', '--map-group', '--map-users', '--map-groups',
        '--root', '--wd',
      ])
    case 'nsenter':
      return skipFlags(words, at + 1, ['-t', '--target', '-S', '--setuid', '-G', '--setgid', '-R', '--root', '-w', '--wd'])
    case 'xvfb-run':
      return skipFlags(words, at + 1, ['-s', '-f', '-n', '-p'])
    case 'time':
      return skipFlags(words, at + 1)
    case 'xargs':
      return skipFlags(words, at + 1, [
        '-I', '-n', '--max-args', '-P', '--max-procs', '-L',
        '-s', '--max-chars', '-a', '--arg-file', '-E', '-d', '--delimiter',
        '--process-slot-var',
      ])
    case 'su':
    case 'runuser': {
      const command = words.slice(at + 1)
      const index = flagIndex(command, ['-c', '--command', '--session-command'])
      let payload = index === -1 ? undefined : command[index + 1]
      if (index === -1) {
        const equals = command.find((word) =>
          word.value.startsWith('--command=') || word.value.startsWith('--session-command='),
        )
        if (equals !== undefined) {
          payload = { value: equals.value.slice(equals.value.indexOf('=') + 1), quoted: true }
        }
      }
      if (index !== -1 && payload === undefined) {
        return hit('SHELL_UNINSPECTABLE', `\`${name} -c\` has no command text`)
      }
      if (payload !== undefined) {
        if (payload.value === '') {
          return hit('SHELL_UNINSPECTABLE', `\`${name} -c\` has no command text`)
        }
        if (isDynamic(payload.value)) {
          return hit('SHELL_UNINSPECTABLE', `the \`${name} -c\` payload is built at runtime`)
        }
        return analyzeText(payload.value, dialect, depth + 1) ?? 'allow'
      }
      if (name === 'runuser') {
        const next = skipFlags(command, 0, ['-u', '--user', '-g', '--group', '-G', '--supp-group', '-s', '--shell', '--session-command'])
        if (next < command.length) return at + 1 + next
      }
      return 'allow'
    }
    case 'watch':
    case 'parallel': {
      const next = skipFlags(words, at + 1, [
        '-n', '--interval', '-d', '--differences', '-j', '--jobs', '-S', '--sshlogin',
        '--delay', '--joblog', '--results', '--sshloginfile', '--workdir', '--tmpdir',
        '--env', '--timeout', '--retries', '--load', '--memfree', '--arg-file', '--colsep',
      ])
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

const START_PROCESS_VALUE_FLAGS = new Set([
  '-filepath',
  '-workingdirectory',
  '-windowstyle',
  '-verb',
  '-credential',
  '-redirectstandardinput',
  '-redirectstandardoutput',
  '-redirectstandarderror',
  '-argumentlist',
  '-args',
  '-environment',
])

const START_PROCESS_BOOL_FLAGS = new Set([
  '-nonewwindow',
  '-wait',
  '-passthru',
  '-usenewenvironment',
  '-loaduserprofile',
])

function expandCommaArgs(words) {
  const expanded = []
  for (const word of words) {
    let raw = word.value.replace(/,$/, '')
    if (raw === '') continue
    while (true) {
      const comma = raw.indexOf(',')
      if (comma === -1) break
      const head = raw.slice(0, comma)
      if (!/^(?:-[A-Za-z-]+|\/[ck])$/i.test(head)) break
      expanded.push({ ...word, value: head })
      raw = raw.slice(comma + 1)
    }
    if (raw !== '') expanded.push({ ...word, value: raw })
  }
  return expanded
}

/** Follow a PowerShell process launcher into the command it starts. */
function analyzeLauncher(name, args, depth) {
  let execWord
  let execIndex = -1
  const filePathFlag = flagIndexCI(args, ['-filepath'])
  if (filePathFlag !== -1) {
    execWord = args[filePathFlag + 1]
    if (execWord === undefined || execWord.value.trim() === '') {
      return hit('SHELL_UNINSPECTABLE', `\`${name} -FilePath\` has no executable`)
    }
  } else {
    for (let i = 0; i < args.length; i += 1) {
      const lower = args[i].value.toLowerCase()
      if (START_PROCESS_VALUE_FLAGS.has(lower)) {
        i += 1
        while (i < args.length && args[i].value.endsWith(',') && i + 1 < args.length) i += 1
        continue
      }
      if (lower.startsWith('-')) continue
      execWord = args[i]
      execIndex = i
      break
    }
  }
  if (execWord === undefined || execWord.value.trim() === '') return null
  if (isDynamic(execWord.value)) {
    return hit('SHELL_UNINSPECTABLE', `the \`${name}\` executable is built at runtime`)
  }

  const executable = commandName(execWord.value)
  const interpreter = interpreterFlags(executable)
  const isShell = SHELLS.has(executable) || executable === 'wsl'
  const isRecognized =
    isShell ||
    interpreter !== undefined ||
    DELETION.has(executable) ||
    WRAPPERS.has(executable) ||
    executable === 'find' ||
    executable === 'git' ||
    executable === 'rsync' ||
    executable === 'robocopy'
  if (!isRecognized) return null

  const rawArgs = []
  const argFlag = flagIndexCI(args, ['-argumentlist', '-args'])
  if (argFlag !== -1) {
    for (let i = argFlag + 1; i < args.length; i += 1) {
      const lower = args[i].value.toLowerCase()
      if (START_PROCESS_VALUE_FLAGS.has(lower) || START_PROCESS_BOOL_FLAGS.has(lower)) break
      rawArgs.push(args[i])
    }
  } else if (execIndex !== -1) {
    for (let i = execIndex + 1; i < args.length; i += 1) {
      const lower = args[i].value.toLowerCase()
      if (START_PROCESS_VALUE_FLAGS.has(lower)) {
        i += 1
        while (i < args.length && args[i].value.endsWith(',') && i + 1 < args.length) i += 1
        continue
      }
      if (START_PROCESS_BOOL_FLAGS.has(lower)) continue
      rawArgs.push(args[i])
    }
  }

  const expandedArgs = expandCommaArgs(rawArgs)
  const dialect = executable === 'pwsh' || executable === 'powershell' ? 'pwsh' : executable === 'cmd' ? 'cmd' : 'posix'
  const synthSegment = {
    words: [{ value: executable, quoted: false, startsQuoted: false, redirect: false }, ...expandedArgs],
    piped: false,
    call: false,
    redirectIn: false,
    expectRedirect: false,
  }
  return analyzeSegment(synthSegment, dialect, depth + 1)
}

/** Does the word at `words[index]` start a deletion command? */
function deletionHit(name, args, dialect, depth) {
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
        if (next === undefined || next.value.trim() === '') {
          return hit('SHELL_UNINSPECTABLE', '`find ' + value + '` has no command to inspect')
        }
        if (isDynamic(next.value)) {
          return hit('SHELL_UNINSPECTABLE', '`find ' + value + '` runs a command built at runtime')
        }
        const commandWords = []
        let cursor = index + 1
        for (; cursor < args.length; cursor += 1) {
          const word = args[cursor]
          if (word.value === ';' || word.value === '+' || word.value === '\\;') break
          commandWords.push({ ...word, redirect: false })
        }
        if (commandWords.length === 0) {
          return hit('SHELL_UNINSPECTABLE', '`find ' + value + '` has no command to inspect')
        }
        const nested = analyzeSegment(
          { words: commandWords, piped: false, call: false, redirectIn: false, expectRedirect: false },
          dialect,
          depth + 1,
        )
        if (nested !== null) {
          return nested.code === 'SHELL_DELETE'
            ? hit('SHELL_DELETE', '`find ' + value + ' ' + next.value + ' ...` deletes every path it matches')
            : nested
        }
        index = cursor
      }
    }
    return null
  }

  if (name === 'git') {
    const subIndex = skipFlags(args, 0, [
      '-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env',
    ])
    const subcommand = args[subIndex]?.value
    const subArgs = args.slice(subIndex + 1)
    const dashDash = subArgs.findIndex((word) => word.value === '--')
    const optionArgs = dashDash === -1 ? subArgs : subArgs.slice(0, dashDash)
    if (subcommand === 'clean' && optionArgs.some((word) => /^-[A-Za-z]*f/.test(word.value) || word.value === '--force')) {
      return hit('SHELL_DELETE', '`git clean -f` permanently removes untracked files')
    }
    if (subcommand === 'rm' && !optionArgs.some((word) => word.value === '--cached')) {
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
  if (depth > 3) return hit('SHELL_TOO_DEEP', 'the shell payload is nested more than 3 levels deep')
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
    let name = dialect === 'cmd' ? cmdCommandName(words[index].value) : commandName(words[index].value)
    if (KEYWORDS.has(name)) {
      index += 1
      if (dialect === 'cmd' && name === 'if') index = skipCmdIfHeader(words, index)
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

  if (index < words.length && steps >= 12) {
    const remaining = dialect === 'cmd' ? cmdCommandName(words[index].value) : commandName(words[index].value)
    if (KEYWORDS.has(remaining) || WRAPPERS.has(remaining)) {
      return hit('SHELL_TOO_DEEP', 'the command nests too many shell wrappers or keywords to inspect')
    }
  }

  if (index >= words.length) return null
  words = words.slice(index)
  const name = dialect === 'cmd' ? cmdCommandName(words[0].value) : commandName(words[0].value)
  const args = words.slice(1)
  if (name === '') return null
  // PowerShell object methods such as `(Get-Item x).Delete()` become a
  // `.Delete` segment after the parenthesis is split away. They are native
  // deletions, not Remove-Item aliases, so catch the method-segment spelling.
  if (dialect === 'pwsh' && name.endsWith('.delete')) {
    return hit('SHELL_DELETE', `the command invokes the .NET method \`${clip(words[0].value)}\``)
  }

  // In PowerShell a quoted string at statement position is an expression, not
  // a command; executing it requires the call operator, which marks the
  // segment. `$x = 'rm'` and `@('rm')` must not be refused.
  if (dialect === 'pwsh' && words[0].startsQuoted === true && segment.call !== true) return null

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
      const attachedSwitch =
        cmdIndex === -1 &&
        dialect === 'cmd' &&
        /^cmd(?:\.exe)?\/[ck]$/i.test(decodeCmdCarets(words[0].value.trim()))
      if (cmdIndex === -1 && !attachedSwitch) return null
      const start = attachedSwitch ? 0 : cmdIndex + 1
      const payload = args[start]
      if (payload === undefined || payload.value === '') {
        return hit('SHELL_UNINSPECTABLE', '`cmd /c` has no command text')
      }
      if (isDynamic(payload.value)) return hit('SHELL_UNINSPECTABLE', 'the `cmd /c` payload is built at runtime')
      const joined = args.length > start + 1 ? args.slice(start).map((word) => word.value).join(' ') : payload.value
      return analyzeText(joined, 'cmd', depth + 1)
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
        const joined =
          args.length > command + 2 ? args.slice(command + 1).map((word) => word.value).join(' ') : payload.value
        return analyzeText(joined, 'pwsh', depth + 1)
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
    let rest = args
    if (name === 'eval') {
      if (rest[0]?.value === '--') rest = rest.slice(1)
    } else if (rest[0] !== undefined && /^-(?:command|c)$/i.test(rest[0].value)) {
      rest = rest.slice(1)
    }
    if (rest.length === 0) {
      if (segment.piped || segment.redirectIn) {
        return hit('SHELL_UNINSPECTABLE', `\`${name}\` reads its program from stdin, so its contents cannot be inspected`)
      }
      return null
    }
    if (rest.some((word) => isDynamic(word.value))) {
      return hit('SHELL_UNINSPECTABLE', `the \`${name}\` payload is built at runtime`)
    }
    return analyzeText(rest.map((word) => word.value).join(' '), name === 'eval' ? 'posix' : 'pwsh', depth + 1)
  }

  return deletionHit(name, args, dialect, depth)
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
  if (dialect === 'pwsh' && /\[scriptblock\]\s*::\s*create/i.test(text)) {
    return hit('SHELL_UNINSPECTABLE', 'the command builds a PowerShell script block at runtime')
  }

  const lexed = lex(text, dialect)
  if (lexed.error !== undefined) return hit('SHELL_UNINSPECTABLE', lexed.error)
  if (lexed.commandSubstitution === true) {
    return hit(
      'SHELL_UNINSPECTABLE',
      'a command substitution appears in command position, so the executed command name is built at runtime',
    )
  }
  for (const segment of lexed.segments) {
    const result = analyzeSegment(segment, dialect, depth)
    if (result !== null) return result
  }
  return null
}
