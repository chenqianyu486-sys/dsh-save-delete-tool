// `restore_file`: undo a delete by moving the archive back.

import { formatText } from '../format.js'
import { argumentsObject, assertMutationAllowed, optionalBoolean, requiredString, textBlock, workspaceFor } from './shared.js'

/**
 * @param {object} options
 * @param {any} options.ctx
 * @param {(root: string) => import('../trash.js').TrashStore} options.getStore
 */
export function createRestoreFileTool({ ctx, getStore }) {
  return {
    name: 'restore_file',
    description: 'Move a trashed item back to its original path. Missing parent directories are recreated.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        trash_id: {
          type: 'string',
          description: 'From `delete_file` or `list_trash`.',
        },
        overwrite: {
          type: 'boolean',
          default: false,
          description: 'Move the current occupant to the trash instead of refusing.',
        },
      },
      required: ['trash_id'],
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          path: { type: 'string' },
          kind: { type: 'string', enum: ['file', 'directory', 'symlink'] },
          replaced_trash_id: { type: 'string' },
          message: { type: 'string' },
        },
        required: ['ok', 'path', 'kind', 'message'],
      },
      render: (_args, value) => textBlock(formatText(value?.message, 600)),
    },
    isConcurrencySafe() {
      return false
    },
    // Host-local presentation only: the shipped Web client derives its own card
    // from the raw arguments, so this method does not drive that UI.
    presentCall(args) {
      return { card: 'generic', title: `Restore ${args?.trash_id ?? ''}`.trim(), kind: 'move' }
    },
    async execute(args, exec) {
      const input = argumentsObject(args)
      const trashId = requiredString(input, 'trash_id')
      const overwrite = optionalBoolean(input, 'overwrite', false)
      assertMutationAllowed(ctx, exec)
      const { store } = await workspaceFor(ctx, exec, getStore)
      return store.restore(trashId, { overwrite })
    },
  }
}
