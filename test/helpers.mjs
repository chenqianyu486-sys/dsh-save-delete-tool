import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

/** A disposable workspace rooted in the OS temp directory. */
export function workspace() {
  const root = mkdtempSync(path.join(tmpdir(), 'dsh-safe-delete-tool-'))
  return {
    root,
    write(relative, text = '') {
      const absolute = path.join(root, ...relative.split('/'))
      mkdirSync(path.dirname(absolute), { recursive: true })
      writeFileSync(absolute, text)
      return absolute
    },
    mkdir(relative) {
      const absolute = path.join(root, ...relative.split('/'))
      mkdirSync(absolute, { recursive: true })
      return absolute
    },
    dispose() {
      rmSync(root, { recursive: true, force: true })
    },
  }
}

/** Create a symlink, or report that this Windows session lacks the privilege. */
export function trySymlink(target, link, type) {
  const attempts = type === 'dir' ? [type, 'junction'] : [type]
  for (const attempt of attempts) {
    try {
      symlinkSync(target, link, attempt)
      return true
    } catch (error) {
      const retryable = error?.code === 'EPERM' || error?.code === 'EACCES' || error?.code === 'UNKNOWN'
      if (!retryable) throw error
    }
  }
  return false
}

/**
 * A Cordis-shaped context with the services these tools use. It records the
 * registrations so tests can invoke the real guard and tool definitions.
 *
 * @param {string} root - the session workspace.
 * @param {{ sandboxMode?: 'read-only' | 'workspace-write' | 'danger-full-access', sandbox?: (request: object) => object }} [options]
 *   `sandboxMode` mounts a `sandboxPolicy` stub returning that mode; `sandbox`
 *   supplies the whole resolver (for a resolver that throws or returns a
 *   foreign shape). Omit both to model a host without the policy service.
 */
export function fakeContext(root, options = {}) {
  const tools = new Map()
  const guards = []
  const preExecute = []
  const sections = []
  const services = {
    workingDirectory: {
      async ensure() {
        return options.workingDirectoryRoot ?? root
      },
      get() {
        return options.workingDirectoryRoot ?? root
      },
    },
  }
  const sandboxCalls = []
  if (options.sandbox !== undefined) {
    services.sandboxPolicy = {
      resolve(request) {
        sandboxCalls.push(request)
        return options.sandbox(request)
      },
    }
  } else if (options.sandboxMode !== undefined) {
    services.sandboxPolicy = {
      resolve(request) {
        sandboxCalls.push(request)
        return { mode: options.sandboxMode, workspaceRoot: root }
      },
    }
  }
  const ctx = {
    tools: {
      register(definition) {
        tools.set(definition.name, definition)
        return () => tools.delete(definition.name)
      },
      guard(callback) {
        guards.push(callback)
        return () => {}
      },
      get(name) {
        return tools.get(name)
      },
    },
    get(name) {
      return services[name]
    },
    on(event, callback) {
      if (event === 'tools/pre-execute') preExecute.push(callback)
      return () => {}
    },
    effect(callback) {
      const dispose = callback()
      return typeof dispose === 'function' ? dispose : () => {}
    },
    inject(_dependencies, callback) {
      callback({
        systemPrompt: {
          section(section) {
            sections.push(section)
            return () => {}
          },
        },
        effect: ctx.effect,
      })
    },
  }
  return { ctx, tools, guards, preExecute, sections, sandboxCalls }
}

/** One tool execution with a schema, arguments and a session workspace. */
export function execution(name, args, parameters, root, sessionId = 'session-test') {
  return {
    name,
    arguments: args,
    schema: parameters === undefined ? undefined : { name, description: '', parameters },
    signal: new AbortController().signal,
    agent: {
      id: 'agent-test',
      session: { id: sessionId, header: { cwd: root } },
    },
  }
}

/** A JSON-schema object parameter spec. */
export function objectSchema(properties) {
  return { type: 'object', properties }
}
