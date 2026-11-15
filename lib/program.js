// Program deletion policy for `run_code` (PTC) and any future program tool.
//
// A program can delete without ever forming a shell command:
// `await import('node:fs')` followed by `fs.rmSync(dir, { recursive: true })`
// is invisible to a shell guard. The scan below is lexical on purpose: it blanks
// comments and string literals before looking for filesystem deletions, keeps
// template expressions visible, and reads the literal command of a
// `child_process`/`execa`/`Deno.Command` call through the shell analyzer.
//
// Like the shell layer this is a guardrail, not a sandbox. Aliases, computed
// properties (`fs['rmSync']`) and a deletion function assembled at runtime are
// outside what a text scan can see; SECURITY.md states that.

import { analyzeShell } from './shell.js'

const MAX_CHARS = 64 * 1024

const FS_DELETIONS = [
  { pattern: /\bfs\s*\.\s*promises\s*\.\s*(?:rm|unlink|rmdir)\s*\(/, label: 'fs.promises.rm' },
  { pattern: /\bfsp\s*\.\s*(?:rm|unlink|rmdir)\s*\(/, label: 'fs.promises.rm' },
  { pattern: /\bfs\s*\.\s*(?:rmSync|rm|unlinkSync|unlink|rmdirSync|rmdir)\s*\(/, label: 'fs.rm' },
  { pattern: /\b(?:fsExtra|fse)\s*\.\s*(?:removeSync|remove|emptyDirSync|emptyDir)\s*\(/, label: 'fs-extra.remove' },
  { pattern: /\brimraf\s*\.\s*sync\s*\(/, label: 'rimraf.sync' },
  { pattern: /\b(?:rimraf|rimrafSync)\s*\(/, label: 'rimraf' },
  // `require` string arguments are blanked, so this matches any
  // require(...).rm-style call. A require result exposing a method named rm
  // is rare; keeping this pattern preserves the old coverage for
  // require('fs').rmSync without treating every `repo.rm()` as deletion.
  { pattern: /\brequire\s*\(\s*\)\s*\.\s*(?:promises\s*\.\s*)?(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\(/, label: 'fs.rm' },
  // Bare imports/aliases still delete; a method receiver (`repo.rm`) does not.
  { pattern: /(?<![.\w])rm(?:Sync)?\s*\(/, label: 'rm' },
  { pattern: /(?<![.\w])(?:unlinkSync|unlink|rmdirSync|rmdir)\s*\(/, label: 'unlink' },
  { pattern: /\b(?:Deno\s*\.\s*remove|shutil\s*\.\s*rmtree|os\s*\.\s*(?:remove|unlink|rmdir))\s*\(/, label: 'os.remove' },
]

const UNINSPECTABLE = [
  /\b(?:eval|new\s+Function)\s*\(/,
  /\bvm\s*\.\s*runIn(?:ThisContext|NewContext|Context)\s*\(/,
  /\bprocess\s*\.\s*(?:binding|getBuiltinModule)\s*\(/,
]

const SHELL_OUT =
  /\b(execSync|execFileSync|execFile|exec|spawnSync|spawn|execaSync|execa|Deno\s*\.\s*Command|Bun\s*\.\s*spawn|pwsh|powershell|bash|sh|zsh|shell|run_command|execute_command|wsl|terminal_send)\s*\(/g

const PROGRAM_OUT = /\b(run_code)\s*\(/g

const INLINE_FLAGS = new Set(['-c', '-e', '-E', '-r', '--eval', '-p', '--print', 'eval', '-command', '/c'])

/** Tool names that take their command as an argument object, not via child_process. */
const BOUND_SHELL_TOOLS = new Set([
  'pwsh',
  'powershell',
  'bash',
  'sh',
  'zsh',
  'shell',
  'run_command',
  'execute_command',
  'wsl',
  'terminal_send',
  'cmd',
])

/** Argument names that carry executable text on a bound shell tool. */
const BOUND_COMMAND_KEYS = new Set(['command', 'cmd', 'commandline', 'command_line', 'text', 'stdin', 'input'])

/** Argument names that are metadata and must never be read as a command. */
const BOUND_METADATA_KEYS = new Set([
  'description',
  'workdir',
  'workingdirectory',
  'justification',
  'timeoutms',
  'timeout',
  'runinbackground',
  'sandbox_permissions',
  'env',
  'distro',
  'translatepaths',
  'asroot',
  'allowdangerous',
  'keepterminal',
  'subtask',
  'result',
  'reason',
  'action',
  'submit',
  'title',
  'sessionid',
  'session_id',
])

/** Map a nested shell/program verdict to the program-level refusal code. */
function shellOutCode(result) {
  return result.code === 'SHELL_DELETE' || result.code === 'PROGRAM_DELETE'
    ? 'PROGRAM_SHELL_DELETE'
    : 'PROGRAM_UNINSPECTABLE'
}

/** Shell executables whose inline payload is shell text, not a JS program. */
const INLINE_SHELLS = new Set(['bash', 'sh', 'zsh', 'pwsh', 'powershell', 'cmd'])

/** Pick the shell dialect for a bound tool name. */
function shellDialectFor(name) {
  const base = String(name).toLowerCase()
  if (base.includes('pwsh') || base.includes('powershell')) return 'pwsh'
  if (base === 'cmd' || base === 'cmd.exe') return 'cmd'
  return 'posix'
}

/** Pick the shell dialect from a literal command name such as "pwsh" or "bash". */
function commandDialect(value) {
  const base = String(value)
    .trim()
    .split(/[\\/]/)
    .pop()
    ?.toLowerCase()
    .replace(/\.(?:exe|cmd|bat|com)$/, '')
  return shellDialectFor(base ?? '')
}

/** The object key immediately before a string literal, or '' for a positional argument. */
function argumentKey(code, start) {
  const before = code.slice(0, start).replace(/\s+$/, '')
  const match = /(?:(['"])([A-Za-z_$][\w$]*)\1|([A-Za-z_$][\w$]*))\s*:\s*$/.exec(before)
  if (match === null) return ''
  return (match[2] ?? match[3] ?? '').toLowerCase()
}

/**
 * Blank calls to locally defined functions whose names collide with deletion
 * verbs. `function unlink(x) { return x }` is not a file deletion, but a bare
 * `unlink(` call still matches the import/alias guard when the function is
 * declared locally. Only declarations whose right-hand side is a function or
 * arrow are masked; `const unlink = fs.unlink` stays dangerous and is still
 * caught.
 */
function maskLocalFunctionDeclarations(blank) {
  const names = new Set()
  const declaration = /\b(?:const|let|var)\s+(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/g
  for (const match of blank.matchAll(/\bfunction\s+(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\(/g)) {
    names.add(match[1])
  }
  for (const match of blank.matchAll(declaration)) names.add(match[1])
  if (names.size === 0) return blank

  let result = blank
  for (const name of names) {
    const call = new RegExp(`(?<![.\\w])${name}\\s*\\(`, 'g')
    result = result.replace(call, (matched) => ' '.repeat(matched.length))
  }
  return result
}

/**
 * Interpret one literal that follows an interpreter flag. Python one-liners
 * frequently use a from-import and then call the imported deletion helper,
 * which the JS-shaped patterns in analyzeProgram do not recognize.
 */
function analyzeInterpreterSource(name, code) {
  if (typeof code !== 'string' || code.trim() === '') return null
  const base = String(name).toLowerCase()
  if (/^python\d*(?:\.\d+)*$/.test(base)) {
    const imports = /\bfrom\s+(?:os|shutil)\s+import\b[^;\n]*\b(?:remove|unlink|rmdir|rmtree)\b/.test(code)
    const calls = /\b(?:remove|unlink|rmdir|rmtree)\s*\(/.test(code)
    if (imports && calls) {
      return hit('PROGRAM_DELETE', 'the program imports a Python deletion helper and calls it')
    }
  }
  if (INLINE_SHELLS.has(base)) {
    const dialect = base === 'pwsh' || base === 'powershell' ? 'pwsh' : base === 'cmd' ? 'cmd' : 'posix'
    const shell = analyzeShell(code, { dialect })
    if (shell !== null) return shell
  }
  return analyzeProgram(code)
}

/** Can a slash at this point start a regex literal rather than a division? */
function regexCanStart(blank) {
  let index = blank.length - 1
  while (index >= 0 && /\s/.test(blank[index])) index -= 1
  if (index < 0) return true
  if ('=([{,:;!&|?+-*%^~<>}'.includes(blank[index])) return true
  let start = index
  while (start >= 0 && /[A-Za-z_$]/.test(blank[start])) start -= 1
  const word = blank.slice(start + 1, index + 1).join('')
  return /^(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/.test(word)
}

/** Scan one regex literal, returning its end offset or null when this is a division. */
function readRegex(code, start) {
  let index = start + 1
  let inClass = false
  while (index < code.length) {
    const char = code[index]
    if (char === '\\') {
      index += 2
      continue
    }
    if (char === '\n' || char === '\r') return null
    if (char === '[') inClass = true
    else if (char === ']') inClass = false
    else if (char === '/' && !inClass) {
      index += 1
      while (index < code.length && /[A-Za-z]/.test(code[index])) index += 1
      return { end: index }
    }
    index += 1
  }
  return null
}

function hit(code, reason) {
  return { code, reason }
}

function clip(value, max = 80) {
  const flat = String(value)
    // eslint-disable-next-line no-control-regex -- refusal text must stay one line
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat
}

function decodeEscape(code, index) {
  const next = code[index + 1]
  switch (next) {
    case 'n': return { value: '\n', end: index + 2 }
    case 'r': return { value: '\r', end: index + 2 }
    case 't': return { value: '\t', end: index + 2 }
    case 'b': return { value: '\b', end: index + 2 }
    case 'f': return { value: '\f', end: index + 2 }
    case 'v': return { value: '\v', end: index + 2 }
    case '0': return { value: '\0', end: index + 2 }
    case 'x': {
      const match = /^[0-9A-Fa-f]{2}/.exec(code.slice(index + 2, index + 4))
      if (match === null) return { value: 'x', end: index + 2 }
      return { value: String.fromCharCode(Number.parseInt(match[0], 16)), end: index + 4 }
    }
    case 'u': {
      if (code[index + 2] === '{') {
        const close = code.indexOf('}', index + 3)
        if (close === -1) return { value: 'u', end: index + 2 }
        const value = Number.parseInt(code.slice(index + 3, close), 16)
        return { value: Number.isFinite(value) ? String.fromCodePoint(value) : '', end: close + 1 }
      }
      const match = /^[0-9A-Fa-f]{4}/.exec(code.slice(index + 2, index + 6))
      if (match === null) return { value: 'u', end: index + 2 }
      return { value: String.fromCharCode(Number.parseInt(match[0], 16)), end: index + 6 }
    }
    case '\n': return { value: '', end: index + 2 }
    case undefined: return { value: '\\', end: index + 1 }
    default: return { value: next, end: index + 2 }
  }
}

/** Index just after the `}` matching the `{` before `index`, skipping nested strings. */
function matchingBrace(code, index) {
  let depth = 1
  let cursor = index
  while (cursor < code.length) {
    const char = code[cursor]
    if (char === "'" || char === '"' || char === '`') {
      const quote = char
      cursor += 1
      while (cursor < code.length) {
        if (code[cursor] === '\\') {
          cursor += 2
          continue
        }
        if (code[cursor] === quote) {
          cursor += 1
          break
        }
        cursor += 1
      }
      continue
    }
    if (char === '{') depth += 1
    else if (char === '}') {
      depth -= 1
      if (depth === 0) return cursor
    }
    cursor += 1
  }
  return -1
}

/**
 * Lex one string or template literal.
 * @returns {{ value: string, start: number, end: number, dynamic: boolean, expressions: Array<{ start: number, end: number }> } | null}
 */
function readString(code, start) {
  const quote = code[start]
  let index = start + 1
  let value = ''
  let dynamic = false
  const expressions = []

  while (index < code.length) {
    const char = code[index]
    if (char === '\\') {
      const decoded = decodeEscape(code, index)
      value += decoded.value
      index = decoded.end
      continue
    }
    if (quote === '`' && char === '$' && code[index + 1] === '{') {
      const close = matchingBrace(code, index + 2)
      if (close === -1) return null
      dynamic = true
      const expression = code.slice(index + 2, close)
      expressions.push({ start: index, end: close + 1 })
      value += `\${${expression}}`
      index = close + 1
      continue
    }
    if (char === quote) {
      return { value, start, end: index + 1, dynamic, expressions }
    }
    value += char
    index += 1
  }
  return null
}

/**
 * Blank comments and string contents while keeping template expressions, and
 * collect the strings for shell-out inspection.
 */
function scan(code) {
  const blank = []
  const strings = []
  let index = 0

  while (index < code.length) {
    const char = code[index]
    const next = code[index + 1]

    if (char === '/' && next === '/') {
      while (index < code.length && code[index] !== '\n') {
        blank.push(' ')
        index += 1
      }
      continue
    }
    if (char === '/' && next === '*') {
      blank.push(' ', ' ')
      index += 2
      while (index < code.length && !(code[index] === '*' && code[index + 1] === '/')) {
        blank.push(code[index] === '\n' ? '\n' : ' ')
        index += 1
      }
      if (index < code.length) {
        blank.push(' ', ' ')
        index += 2
      }
      continue
    }
    if (char === '/' && next !== '/' && next !== '*') {
      if (regexCanStart(blank)) {
        const literal = readRegex(code, index)
        if (literal !== null) {
          for (let cursor = index; cursor < literal.end; cursor += 1) {
            blank.push(code[cursor] === '\n' ? '\n' : ' ')
          }
          index = literal.end
          continue
        }
      }
    }
    if (char === "'" || char === '"' || char === '`') {
      const literal = readString(code, index)
      if (literal === null) return null
      strings.push(literal)
      for (let cursor = literal.start; cursor < literal.end; cursor += 1) {
        const insideExpression = literal.expressions.some(
          (expression) => cursor >= expression.start && cursor < expression.end,
        )
        if (insideExpression) blank.push(code[cursor])
        else blank.push(code[cursor] === '\n' ? '\n' : ' ')
      }
      index = literal.end
      continue
    }
    blank.push(char)
    index += 1
  }

  return { blank: blank.join(''), strings }
}

function callEnd(blank, from) {
  let depth = 1
  for (let index = from; index < blank.length; index += 1) {
    if (blank[index] === '(') depth += 1
    else if (blank[index] === ')') {
      depth -= 1
      if (depth === 0) return index
    }
  }
  return Math.min(blank.length, from + 600)
}

function shellOutHit(blank, strings, code) {
  // A local RegExp keeps this loop re-entrant: analyzing a literal can call
  // back into this module, and a shared lastIndex would restart the scan.
  const pattern = new RegExp(SHELL_OUT.source, 'g')
  let match
  let inspected = 0
  while ((match = pattern.exec(blank)) !== null && inspected < 100) {
    inspected += 1
    const rawTool = match[1].replace(/\s+/g, '')
    const tool = rawTool.toLowerCase()
    const from = match.index + match[0].length
    const end = callEnd(blank, from)
    const callStrings = strings.filter((entry) => entry.start >= from && entry.start < end)
    if (callStrings.length === 0) continue

    if (BOUND_SHELL_TOOLS.has(tool)) {
      const dialect = shellDialectFor(tool)
      for (const literal of callStrings) {
        if (literal.value.trim() === '') continue
        // A quoted object key is not an argument value; skip the literal that
        // is followed by `:` so a property named `rm` cannot trip the shell
        // analyzer on its own.
        if (/^\s*:/.test(code.slice(literal.end))) continue
        const key = argumentKey(code, literal.start)
        if (key === '') {
          if (literal !== callStrings[0]) continue
        } else if (BOUND_METADATA_KEYS.has(key)) {
          continue
        } else if (!BOUND_COMMAND_KEYS.has(key)) {
          continue
        }
        const result = analyzeShell(literal.value, { dialect })
        if (result !== null) {
          return hit(
            shellOutCode(result),
            'the program passes `' + clip(literal.value) + '` to `' + rawTool + '`: ' + result.reason,
          )
        }
      }
      continue
    }

    // child_process / execa / Deno.Command / Bun.spawn: analyze the command
    // name and the argv joined together, never each literal on its own.
    const first = callStrings[0]
    if (first !== undefined && first.value.trim() !== '') {
      const joined = callStrings.map((literal) => literal.value).join(' ')
      const result = analyzeShell(joined, { dialect: commandDialect(first.value) })
      if (result !== null) {
        return hit(
          shellOutCode(result),
          'the program runs `' + clip(joined) + '` through `' + rawTool + '`: ' + result.reason,
        )
      }
    }

    // A separate argv element after an interpreter flag is executable source;
    // execFile("python", ["-c", "...; shutil.rmtree(...)"]) must not depend on
    // the joined text preserving its quoting.
    for (let index = 0; index + 1 < callStrings.length; index += 1) {
      if (!INLINE_FLAGS.has(callStrings[index].value)) continue
      const program = analyzeInterpreterSource(first?.value ?? '', callStrings[index + 1].value)
      if (program !== null) {
        return hit(
          shellOutCode(program),
          'the program runs `' + clip(callStrings[index + 1].value) + '` through `' + rawTool + '`: ' + program.reason,
        )
      }
    }
  }
  return null
}

function nestedProgramHit(blank, strings, depth) {
  const pattern = new RegExp(PROGRAM_OUT.source, 'g')
  let match
  while ((match = pattern.exec(blank)) !== null) {
    if (depth >= 2) {
      return hit('PROGRAM_UNINSPECTABLE', '`run_code` is nested more than 2 levels deep')
    }
    const from = match.index + match[0].length
    const end = callEnd(blank, from)
    const callStrings = strings.filter((entry) => entry.start >= from && entry.start < end)
    for (const literal of callStrings) {
      const result = analyzeProgram(literal.value, { depth: depth + 1 })
      if (result !== null) {
        return hit('PROGRAM_NESTED_DELETE', `nested \`run_code\` code ${result.reason}`)
      }
    }
  }
  return null
}

/**
 * Analyze one program body.
 * @param {string} code
 * @param {{ depth?: number }} [options]
 * @returns {{ code: string, reason: string } | null}
 */
export function analyzeProgram(code, options = {}) {
  if (typeof code !== 'string' || code.trim() === '') return null
  if (code.length > MAX_CHARS) {
    return hit('PROGRAM_TOO_LONG', `the program is longer than ${MAX_CHARS} characters, so it could not be inspected`)
  }

  const scanned = scan(code)
  if (scanned === null) {
    return hit('PROGRAM_UNINSPECTABLE', 'the program contains an unterminated string or comment')
  }

  const deletionBlank = maskLocalFunctionDeclarations(scanned.blank)
  for (const entry of FS_DELETIONS) {
    if (entry.pattern.test(deletionBlank)) {
      return hit(
        'PROGRAM_DELETE',
        `the program calls \`${entry.label}\`, which deletes outside the recoverable trash`,
      )
    }
  }

  for (const pattern of UNINSPECTABLE) {
    if (pattern.test(scanned.blank)) {
      return hit(
        'PROGRAM_UNINSPECTABLE',
        'the program evaluates code at runtime, so its filesystem calls cannot be inspected',
      )
    }
  }

  const shellOut = shellOutHit(scanned.blank, scanned.strings, code)
  if (shellOut !== null) return shellOut
  return nestedProgramHit(scanned.blank, scanned.strings, options.depth ?? 0)
}
