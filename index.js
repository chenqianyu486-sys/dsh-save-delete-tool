// dsh-safe-delete-tool
//
// The plugin changes the delete primitive instead of chasing every way a shell
// can spell it: `delete_file` moves the target into a per-item trash, and the
// guard only has to decide whether a tool call is an irreversible delete that
// should be pointed at that tool.
//
// What it registers, and nothing else:
//   1. `delete_file` / `restore_file` / `list_trash` — the model-facing surface;
//   2. one system-prompt paragraph telling the model which surface to use;
//   3. `tools/pre-execute` for the guided refusal and `tools.guard` for the
//      monotonic backstop. The guard is synchronous and independent of listener
//      order, so an approved `ask` cannot re-open the hole.
//
// Tool classification is by schema shape (`command` = shell, `code` = program),
// so the same plugin covers the standard, PTC, minimal and cordis presets: PTC
// adds `run_code`, minimal exposes a persistent `pwsh`, and neither needs a
// per-preset configuration list.

import { TrashStore } from './lib/trash.js'
import { analyzeExecution } from './lib/guard.js'
import { createDeleteFileTool } from './lib/tools/delete-file.js'
import { createRestoreFileTool } from './lib/tools/restore-file.js'
import { createListTrashTool } from './lib/tools/list-trash.js'

export const name = 'safe-delete'
export const inject = ['tools']

/** Kept in sync with package.json by test/contract.test.mjs. */
export const VERSION = '2.0.6'

/** One paragraph, kept short because it is paid for on every request. */
const PROMPT_SECTION = `<safe_delete>
Delete with \`delete_file\`: it moves the target into \`.dsh/trash\` and returns a \`trash_id\` for \`restore_file\`; \`list_trash\` shows what is recoverable. Shell deletion (\`rm\`, \`Remove-Item\`, \`find -delete\`) and program filesystem deletion (\`fs.rm\`, \`unlink\`, \`child_process\`) are refused when the guard recognizes the call; script files and binaries are outside this layer.
</safe_delete>`

function errorInfo(found) {
  return { name: 'safe_delete', code: found.code, reason: found.reason }
}

/**
 * The model-facing refusal. It names what was blocked, the tool to use instead,
 * and the fact that a retry through an alias is not the answer. The policy
 * itself lives in the prompt section, so the refusal stays short.
 */
function denialMessage(found) {
  const where = found.channel === 'program' ? `the \`${found.toolName}\` program` : `\`${found.toolName}\``
  const ambiguous =
    found.code === 'SHELL_UNINSPECTABLE' ||
    found.code === 'SHELL_TOO_LONG' ||
    found.code === 'SHELL_TOO_DEEP' ||
    found.code === 'PROGRAM_UNINSPECTABLE' ||
    found.code === 'PROGRAM_TOO_LONG'
  const what = ambiguous
    ? `a ${found.channel} call the guard could not inspect`
    : `an irreversible ${found.channel} deletion`
  return (
    `[dsh-safe-delete-tool v${VERSION}] Blocked ${what} in ${where}: ${found.reason}. ` +
    'Nothing was deleted. Use `delete_file` instead: it moves the target to `.dsh/trash` and returns a `trash_id` ' +
    'that `restore_file` undoes. Do not retry through an alias, wrapper, nested shell, script or runtime-built string.'
  )
}

/** @param {any} ctx - plugin context. */
export function apply(ctx) {
  // One store per canonical workspace root. Each item is its own directory, so
  // the store needs no cross-call queue to keep records from overwriting one
  // another; the map only avoids rebuilding paths.
  const stores = new Map()
  const getStore = (root) => {
    let store = stores.get(root)
    if (store === undefined) {
      store = new TrashStore({ root })
      stores.set(root, store)
    }
    return store
  }

  const definitions = [
    createDeleteFileTool({ ctx, getStore }),
    createRestoreFileTool({ ctx, getStore }),
    createListTrashTool({ ctx, getStore }),
  ]
  // All three tools are one recoverable surface. Registering delete_file and
  // then silently dropping restore_file would advertise an undo that does not
  // exist, so registration is all-or-nothing: on the first failure, dispose the
  // tools that did register and install no prompt, guard or pre-execute layer.
  const disposers = []
  let registrationFailure = null
  for (const definition of definitions) {
    try {
      const dispose = ctx.effect(() => ctx.tools.register(definition))
      if (typeof dispose === 'function') disposers.push(dispose)
    } catch (error) {
      registrationFailure = { definition, error }
      break
    }
  }

  if (registrationFailure !== null) {
    for (const dispose of disposers.reverse()) {
      try {
        dispose()
      } catch (error) {
        console.error('dsh-safe-delete-tool: could not undo a partial tool registration', error)
      }
    }
    console.error(
      `dsh-safe-delete-tool: could not register the ${registrationFailure.definition.name} tool, so no tool, prompt section or deletion guard is installed`,
      registrationFailure.error,
    )
    ctx.effect(() => () => stores.clear())
    return
  }

  if (typeof ctx.inject === 'function') {
    try {
      ctx.inject(['systemPrompt'], (inner) => {
        if (typeof inner?.systemPrompt?.section !== 'function') return
        inner.effect(() =>
          inner.systemPrompt.section({
            name: 'safe-delete',
            // 74 sits after the deployment persona (0) and before the first-party
            // tool guidance (>= 1000), which is where a policy paragraph belongs.
            order: 74,
            interpolate: false,
            text: PROMPT_SECTION,
          }),
        )
      })
    } catch (error) {
      console.warn('dsh-safe-delete-tool: could not add the system-prompt guidance', error)
    }
  }

  /**
   * Guided refusal: deny a recognized deletion regardless of whether the
   * inner decision was allow or ask. A stricter deny/cancel is preserved. This
   * keeps the policy effective on hosts whose tools.guard is unavailable; the
   * guard remains a second, monotonic check after approval resolution.
   */
  const preExecute = async (exec, next) => {
    const decision = await next()
    if (decision?.kind === 'deny' || decision?.kind === 'cancel') return decision
    const found = analyzeExecution(exec, ctx.tools)
    if (found === null) return decision
    return { kind: 'deny', reason: denialMessage(found), info: errorInfo(found) }
  }

  /** Monotonic backstop: checked after pre-execute policy and approval resolve. */
  const guard = (execution) => {
    const found = analyzeExecution(execution, ctx.tools)
    return found === null ? undefined : { reason: denialMessage(found), info: errorInfo(found) }
  }

  try {
    ctx.effect(() => ctx.on('tools/pre-execute', preExecute))
  } catch (error) {
    console.error('dsh-safe-delete-tool: could not install the pre-execute guard', error)
  }
  try {
    if (typeof ctx.tools.guard === 'function') ctx.effect(() => ctx.tools.guard(guard))
  } catch (error) {
    console.warn('dsh-safe-delete-tool: tools.guard is unavailable; pre-execute still blocks deletion', error)
  }

  ctx.effect(() => () => stores.clear())
}
