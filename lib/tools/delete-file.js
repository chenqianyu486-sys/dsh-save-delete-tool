// `delete_file`: the structured, recoverable replacement for `rm`.

import { formatText } from '../format.js'
import {
  argumentsObject,
  assertMutationAllowed,
  optionalBoolean,
  optionalString,
  requiredString,
  textBlock,
  workspaceFor,
} from './shared.js'

/**
 * @param {object} options
 * @param {any} options.ctx
 * @param {(root: string) => import('../trash.js').TrashStore} options.getStore
 */
export function createDeleteFileTool({ ctx, getStore }) {
  return {
    name: 'delete_file',
    description:
      'Move a file or directory into the recoverable trash and return a `trash_id`. This is how deletion works here.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: {
          type: 'string',
          description: 'Workspace-relative, or absolute inside the workspace.',
        },
        recursive: {
          type: 'boolean',
          default: false,
          description: 'Required for a non-empty directory.',
        },
        reason: {
          type: 'string',
          description: 'Recorded with the trash item.',
        },
        dry_run: {
          type: 'boolean',
          default: false,
          description: 'Report what would move; change nothing.',
        },
      },
      required: ['path'],
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          dry_run: { type: 'boolean' },
          path: { type: 'string' },
          kind: { type: 'string', enum: ['file', 'directory', 'symlink'] },
          entries: { type: 'number' },
          recursive_required: { type: 'boolean' },
          trash_id: { type: 'string' },
          message: { type: 'string' },
        },
        required: ['ok', 'path', 'kind', 'message'],
      },
      render: (_args, value) => textBlock(formatText(value?.message, 600)),
    },
    isConcurrencySafe(args) {
      return args?.dry_run === true
    },
    // Host-local presentation only: the shipped Web client derives its own card
    // from the raw arguments, so this method does not drive that UI.
    presentCall(args) {
      return {
        card: 'generic',
        title: `${args?.dry_run === true ? 'Preview delete' : 'Trash'} ${args?.path ?? ''}`.trim(),
        kind: 'delete',
        locations: typeof args?.path === 'string' ? [{ path: args.path }] : undefined,
      }
    },
    async execute(args, exec) {
      const input = argumentsObject(args)
      const target = requiredString(input, 'path')
      const recursive = optionalBoolean(input, 'recursive', false)
      const dryRun = optionalBoolean(input, 'dry_run', false)
      const reason = optionalString(input, 'reason', '')
      // A dry run moves nothing, so it stays available in a read-only session.
      if (!dryRun) assertMutationAllowed(ctx, exec)
      const { store, sessionId } = await workspaceFor(ctx, exec, getStore)
      return store.delete(target, { recursive, dryRun, reason, sessionId })
    },
  }
}
