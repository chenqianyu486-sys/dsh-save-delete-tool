// Classify one tool execution and route its payloads to the right analyzer.
//
// The classification is by tool schema, not by a list of tool names: a tool
// whose parameters include a string `command` is a shell, and a tool whose
// parameters include a string `code` is a program. That is what makes the
// plugin work unchanged in every agent preset — `standard` exposes `pwsh`,
// `ptc` adds `run_code`, `minimal` exposes a persistent `pwsh`, and `cordis`
// adds its read-only inspection tools, which have neither parameter.

import { formatText } from './format.js'
import { analyzeProgram } from './program.js'
import { analyzeShell } from './shell.js'

/** Arguments that never carry executable text. */
const METADATA = new Set([
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

const COMMAND_KEYS = new Set(['command', 'cmd', 'commandline', 'command_line'])

const KNOWN_SHELLS = new Set([
  'pwsh',
  'powershell',
  'bash',
  'sh',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'cmd',
  'shell',
  'run_command',
  'execute_command',
  'terminal',
  'wsl',
  'wsl-term',
  'pwsh_persistent',
  'persistent_pwsh',
])

const KNOWN_PROGRAMS = new Set(['run_code'])

const KNOWN_PATCH = new Set(['apply_patch'])

const PATCH_DELETE = /^\*\*\*\s*Delete File:\s*(.+?)\s*$/m

function baseName(value) {
  return String(value).split(/[\\/]/).pop()?.toLowerCase() ?? ''
}

function parseArguments(value) {
  if (value === null || value === undefined) return null
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null
    } catch {
      return null
    }
  }
  return typeof value === 'object' && !Array.isArray(value) ? value : null
}

/** Model-facing parameter properties, from the call or the live registry. */
function propertiesOf(exec, tools) {
  let schema = exec?.schema
  if (schema === undefined && tools !== undefined && typeof tools.get === 'function') {
    try {
      schema = tools.get(exec.name, exec.agent)
    } catch {
      schema = undefined
    }
  }
  const parameters = schema?.parameters
  if (parameters === null || typeof parameters !== 'object') return null
  if (parameters.properties !== null && typeof parameters.properties === 'object') return parameters.properties
  // A raw parameter spec (`{ command: { type: 'string' } }`) before projection.
  if (typeof parameters.type === 'string' && parameters.type !== 'object') return null
  return parameters
}

function isStringParameter(spec) {
  if (spec === null || typeof spec !== 'object') return false
  if (spec.type === 'string' || (Array.isArray(spec.type) && spec.type.includes('string'))) return true
  if (spec.type === 'array' && isStringParameter(spec.items)) return true
  if (Array.isArray(spec.anyOf) && spec.anyOf.some((entry) => isStringParameter(entry))) return true
  if (Array.isArray(spec.oneOf) && spec.oneOf.some((entry) => isStringParameter(entry))) return true
  return false
}

function payloadText(value) {
  if (typeof value === 'string') return value
  if (Array.isArray(value) && value.length > 0 && value.every((part) => typeof part === 'string')) {
    return value.join(' ')
  }
  return null
}

function dialectFor(name) {
  const base = baseName(name)
  if (base.includes('pwsh') || base.includes('powershell')) return 'pwsh'
  if (base === 'cmd' || base.startsWith('cmd.')) return 'cmd'
  return 'posix'
}

/**
 * Analyze one execution.
 * @param {any} exec - `tools/pre-execute` execution or guard execution.
 * @param {any} [tools] - the live tool registry, used when `exec.schema` is absent.
 * @returns {{ code: string, reason: string, toolName: string, channel: 'shell' | 'program' | 'terminal' | 'patch', argument?: string } | null}
 */
export function analyzeExecution(exec, tools) {
  if (exec === null || exec === undefined || typeof exec.name !== 'string') return null
  const args = parseArguments(exec.arguments)
  if (args === null) return null

  const properties = propertiesOf(exec, tools)
  const base = baseName(exec.name)
  let shellShaped = false
  let programShaped = false
  let terminalShaped = false
  let patchShaped = KNOWN_PATCH.has(base)

  if (properties !== null) {
    const keys = Object.keys(properties).map((key) => key.toLowerCase())
    for (const [key, spec] of Object.entries(properties)) {
      if (!isStringParameter(spec)) continue
      if (key.toLowerCase() === 'code') programShaped = true
      else if (COMMAND_KEYS.has(key.toLowerCase())) shellShaped = true
    }
    // `terminal_send` has no command parameter; the command is typed into a
    // live shell through `text`. Recognize that shape too.
    terminalShaped =
      keys.includes('text') && (keys.includes('sessionid') || keys.includes('session_id') || keys.includes('submit'))
  } else {
    shellShaped = KNOWN_SHELLS.has(base)
    programShaped = KNOWN_PROGRAMS.has(base)
    terminalShaped = base.includes('terminal') || base.includes('term')
  }

  const patchInput = typeof args.input === 'string' ? args.input : typeof args.patch === 'string' ? args.patch : null
  if (patchShaped && patchInput !== null) {
    const match = PATCH_DELETE.exec(patchInput)
    if (match !== null) {
      return {
        code: 'PATCH_DELETE',
        reason: `the patch deletes \`${formatText(match[1], 120)}\``,
        toolName: exec.name,
        channel: 'patch',
      }
    }
  }

  if (!shellShaped && !programShaped && !terminalShaped) return null

  if (programShaped) {
    const code = args.code ?? args.program ?? args.source
    if (typeof code === 'string' && code.trim() !== '') {
      const result = analyzeProgram(code)
      if (result !== null) return { ...result, toolName: exec.name, channel: 'program' }
    }
  }

  if (shellShaped || terminalShaped) {
    const dialect = dialectFor(exec.name)
    const channel = shellShaped ? 'shell' : 'terminal'
    for (const [key, value] of Object.entries(args)) {
      if (METADATA.has(key.toLowerCase())) continue
      const text = payloadText(value)
      if (text === null || text.trim() === '') continue
      const result = analyzeShell(text, { dialect })
      if (result !== null) return { ...result, toolName: exec.name, channel, argument: key }
    }
  }

  return null
}
