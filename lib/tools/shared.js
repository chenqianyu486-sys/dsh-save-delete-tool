// Shared argument validation, workspace resolution and the sandbox gate for the
// three tools.

import { fail } from '../errors.js'
import { resolveWorkspace, safeService } from '../paths.js'

/**
 * Refuse a mutation the session's sandbox policy forbids.
 *
 * `delete_file` and `restore_file` move files with `node:fs`, so the Harness
 * filesystem fence (`ctx.fs`) never sees them. Reading the same per-call
 * `ctx.sandboxPolicy` the fence uses keeps a read-only session read-only
 * instead of turning this plugin into the one mutation channel the sandbox
 * cannot close. A composition without the policy service keeps working — the
 * plugin must not require a service the host may not mount — but a policy that
 * exists and cannot be resolved fails closed.
 *
 * @param {any} ctx - plugin context.
 * @param {any} exec - the tool execution.
 */
export function assertMutationAllowed(ctx, exec) {
  const policy = safeService(ctx, 'sandboxPolicy')
  // A composition without the policy service is not gated: the plugin must not
  // require a service the host may not mount (headless and custom presets).
  if (policy === undefined) return
  if (typeof policy.resolve !== 'function') {
    fail(
      'SANDBOX_POLICY_UNAVAILABLE',
      'A sandbox policy service is mounted but exposes no `resolve()`, so the mode cannot be read. ' +
        'Nothing was moved.',
    )
  }

  let mode
  try {
    mode = policy.resolve({ session: exec?.agent?.session })?.mode
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    fail(
      'SANDBOX_POLICY_UNAVAILABLE',
      `The sandbox policy for this call could not be resolved, so nothing was moved: ${message}`,
    )
  }
  if (mode !== 'read-only' && mode !== 'workspace-write' && mode !== 'danger-full-access') {
    fail(
      'SANDBOX_POLICY_UNAVAILABLE',
      `The sandbox policy resolved to an unknown mode (${JSON.stringify(mode)}), so nothing was moved.`,
    )
  }
  if (mode === 'read-only') {
    fail(
      'SANDBOX_READ_ONLY',
      'The session is in read-only mode, so no file may be moved. Nothing was moved. ' +
        'Switch the session to workspace-write (or ask the user to) and retry.',
    )
  }
}

/** One text content block, as `ToolOutputDefinition.render` returns. */
export function textBlock(text) {
  return [{ type: 'text', text }]
}

export function argumentsObject(args) {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) {
    fail('INVALID_ARGUMENTS', 'The tool arguments must be an object.')
  }
  return args
}

export function requiredString(args, key) {
  const value = args[key]
  if (typeof value !== 'string' || value.trim() === '') {
    fail('INVALID_ARGUMENTS', `\`${key}\` must be a non-empty string.`)
  }
  return value
}

export function optionalString(args, key, fallback = '') {
  const value = args[key]
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'string') fail('INVALID_ARGUMENTS', `\`${key}\` must be a string when provided.`)
  return value
}

export function optionalBoolean(args, key, fallback = false) {
  const value = args[key]
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'boolean') fail('INVALID_ARGUMENTS', `\`${key}\` must be a boolean when provided.`)
  return value
}

export function optionalInteger(args, key, fallback, min, max) {
  const value = args[key]
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    fail('INVALID_ARGUMENTS', `\`${key}\` must be a number when provided.`)
  }
  const rounded = Math.trunc(value)
  if (rounded < min || rounded > max) fail('INVALID_ARGUMENTS', `\`${key}\` must be between ${min} and ${max}.`)
  return rounded
}

/**
 * Resolve the workspace and the store for one call.
 * @param {any} ctx
 * @param {any} exec
 * @param {(root: string) => import('../trash.js').TrashStore} getStore
 */
export async function workspaceFor(ctx, exec, getStore) {
  const { root, sessionId } = await resolveWorkspace(ctx, exec)
  return { root, sessionId, store: getStore(root) }
}
