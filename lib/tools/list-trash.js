// `list_trash`: what can still be restored.

import { formatEntries, formatPath, formatText, formatTime } from '../format.js'
import { argumentsObject, optionalInteger, optionalString, textBlock, workspaceFor } from './shared.js'

/**
 * @param {object} options
 * @param {any} options.ctx
 * @param {(root: string) => import('../trash.js').TrashStore} options.getStore
 */
export function createListTrashTool({ ctx, getStore }) {
  return {
    name: 'list_trash',
    description: 'List recoverable trash items, newest first.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        query: {
          type: 'string',
          description: 'Case-insensitive filter over id, path and reason.',
        },
        trash_id: {
          type: 'string',
          description: 'Show one known item instead of a page.',
        },
        limit: {
          type: 'number',
          default: 10,
          description: 'Items to return (1-100).',
        },
        offset: {
          type: 'number',
          default: 0,
          description: 'Items to skip.',
        },
      },
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          items: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                trash_id: { type: 'string' },
                path: { type: 'string' },
                kind: { type: 'string', enum: ['file', 'directory', 'symlink'] },
                entries: { type: 'number' },
                deleted_at: { type: 'string' },
                reason: { type: 'string' },
              },
              required: ['trash_id', 'path', 'kind'],
            },
          },
          total: { type: 'number' },
          trash_total: { type: 'number' },
          offset: { type: 'number' },
        },
        required: ['items', 'total', 'trash_total'],
      },
      render: (_args, value) => textBlock(renderList(value)),
    },
    isConcurrencySafe() {
      return true
    },
    presentCall() {
      return { card: 'generic', title: 'List trash', kind: 'read' }
    },
    async execute(args, exec) {
      const input = argumentsObject(args ?? {})
      const query = optionalString(input, 'query', '')
      const trashId = optionalString(input, 'trash_id', '')
      const limit = optionalInteger(input, 'limit', 10, 1, 100)
      const offset = optionalInteger(input, 'offset', 0, 0, 1_000_000)
      const { store } = await workspaceFor(ctx, exec, getStore)
      return store.list({ query, trashId, limit, offset })
    },
  }
}

function renderList(value) {
  const items = Array.isArray(value?.items) ? value.items : []
  const total = Number(value?.total ?? items.length)
  const trashTotal = Number(value?.trash_total ?? total)
  const offset = Number(value?.offset ?? 0)

  if (trashTotal === 0) return 'The workspace trash is empty.'
  if (items.length === 0) return `No recoverable items match (${trashTotal} in the trash).`

  const lines = [`Recoverable trash: ${items.length} of ${total} shown (${trashTotal} total).`]
  for (const item of items) {
    const id = formatPath(item.trash_id, 80)
    const path = formatPath(item.path, 160)
    const kind = typeof item.kind === 'string' ? item.kind : 'item'
    const shape = kind === 'directory' ? `directory, ${formatEntries(Number(item.entries ?? 0))}` : kind
    const when = formatTime(item.deleted_at)
    const reason = formatText(item.reason, 100)
    lines.push(`- \`${id}\` \`${path}\` — ${shape}${when === '' ? '' : `, ${when}`}${reason === '' ? '' : ` — ${reason}`}`)
  }
  const next = offset + items.length
  if (next < total) lines.push(`Next page: \`list_trash({"offset": ${next}})\`.`)
  return lines.join('\n')
}
