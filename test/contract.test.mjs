// Contract pins that a fake context cannot prove by itself: the shape the Host
// reads from a tool definition, the version the refusal prints, and the rule
// that a refusal is never installed without its recoverable replacement.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { apply, VERSION } from '../index.js'
import { SafeDeleteError } from '../lib/errors.js'
import { execution, fakeContext, workspace } from './helpers.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

test('VERSION matches package.json', () => {
  const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'))
  assert.equal(VERSION, manifest.version)
})

test('every tool matches the documented ToolDefinition contract', () => {
  const space = workspace()
  try {
    const { ctx, tools } = fakeContext(space.root)
    apply(ctx)
    for (const name of ['delete_file', 'restore_file', 'list_trash']) {
      const definition = tools.get(name)
      assert.equal(definition.name, name)
      assert.equal(typeof definition.description, 'string')
      assert.ok(definition.description.length > 0)
      assert.equal(definition.parameters.type, 'object')
      assert.equal(typeof definition.output.schema, 'object')

      // The Host calls render with (args, value) and expects content blocks.
      const rendered = definition.output.render({}, { message: 'x', items: [], total: 0, trash_total: 0 })
      assert.ok(Array.isArray(rendered), `${name}: render must return an array`)
      assert.equal(rendered[0].type, 'text')

      assert.equal(typeof definition.execute, 'function')
      assert.equal(typeof definition.isConcurrencySafe({}), 'boolean')
      if (definition.presentCall !== undefined) {
        assert.equal(typeof definition.presentCall({}).card, 'string')
      }
    }
  } finally {
    space.dispose()
  }
})

test('nothing is installed when delete_file cannot register', () => {
  const space = workspace()
  try {
    const { ctx, tools, guards, preExecute, sections } = fakeContext(space.root)
    const register = ctx.tools.register
    ctx.tools.register = (definition) => {
      if (definition.name === 'delete_file') throw new Error('a tool named delete_file already exists')
      return register(definition)
    }

    apply(ctx)

    assert.equal(tools.size, 0, 'restore/list must not advertise an undo for deletions that cannot happen')
    assert.equal(guards.length, 0, 'a denied rm without delete_file would be a dead end')
    assert.equal(preExecute.length, 0)
    assert.equal(sections.length, 0)
  } finally {
    space.dispose()
  }
})

test('nothing is installed when a companion tool cannot register', () => {
  const space = workspace()
  try {
    const { ctx, tools, guards, preExecute, sections } = fakeContext(space.root)
    const register = ctx.tools.register
    ctx.tools.register = (definition) => {
      if (definition.name === 'restore_file') throw new Error('a tool named restore_file already exists')
      return register(definition)
    }

    apply(ctx)

    assert.equal(tools.size, 0, 'a partial registration must not advertise delete without restore')
    assert.equal(guards.length, 0)
    assert.equal(preExecute.length, 0)
    assert.equal(sections.length, 0)
  } finally {
    space.dispose()
  }
})

test('pre-execute denies a recognized deletion even when another listener asks', async () => {
  const space = workspace()
  try {
    const { ctx, preExecute } = fakeContext(space.root)
    apply(ctx)
    const schema = { type: 'object', properties: { command: { type: 'string' } } }
    const denied = await preExecute[0](
      execution('pwsh', { command: 'rm -rf build' }, schema, space.root),
      async () => ({ kind: 'ask' }),
    )
    assert.equal(denied.kind, 'deny')
    assert.equal(denied.info.code, 'SHELL_DELETE')

    const stricterDeny = { kind: 'deny', reason: 'other plugin' }
    assert.equal(
      await preExecute[0](execution('pwsh', { command: 'rm -rf build' }, schema, space.root), async () => stricterDeny),
      stricterDeny,
      'a stricter decision is preserved',
    )

    const stillAsk = await preExecute[0](
      execution('pwsh', { command: 'git status' }, schema, space.root),
      async () => ({ kind: 'ask' }),
    )
    assert.equal(stillAsk.kind, 'ask', 'a non-deletion keeps the inner decision')
  } finally {
    space.dispose()
  }
})

test('a refusal names the plugin version and the stable code', () => {
  const space = workspace()
  try {
    const { ctx, guards } = fakeContext(space.root)
    apply(ctx)
    const denied = guards[0](
      execution(
        'pwsh',
        { command: 'rm -rf build' },
        { type: 'object', properties: { command: { type: 'string' } } },
        space.root,
      ),
    )
    assert.match(denied.reason, new RegExp(`^\\[dsh-safe-delete-tool v${VERSION}\\] Blocked an irreversible shell deletion`))
    assert.equal(denied.info.code, 'SHELL_DELETE')
  } finally {
    space.dispose()
  }
})

test('a tool failure message carries its stable code', () => {
  const error = new SafeDeleteError('PATH_OUTSIDE_WORKSPACE', 'Refusing to delete "../x".')
  assert.equal(error.code, 'PATH_OUTSIDE_WORKSPACE')
  assert.equal(error.message, '[PATH_OUTSIDE_WORKSPACE] Refusing to delete "../x".')
})

test('tool return values conform to their declared output.schema including session_id', async () => {
  const space = workspace()
  try {
    const { ctx, tools } = fakeContext(space.root, { sandboxMode: 'workspace-write' })
    apply(ctx)
    space.write('item.txt', 'data')

    const deleteDef = tools.get('delete_file')
    const deleted = await deleteDef.execute(
      { path: 'item.txt', reason: 'contract' },
      execution('delete_file', { path: 'item.txt' }, undefined, space.root, 'sess-1'),
    )
    for (const key of deleteDef.output.schema.required) {
      assert.notEqual(deleted[key], undefined, `delete_file missing ${key}`)
    }
    for (const key of Object.keys(deleted)) {
      assert.ok(key in deleteDef.output.schema.properties, `delete_file unexpected key ${key}`)
    }

    const listDef = tools.get('list_trash')
    const listed = await listDef.execute(
      {},
      execution('list_trash', {}, undefined, space.root, 'sess-1'),
    )
    for (const key of listDef.output.schema.required) {
      assert.notEqual(listed[key], undefined, `list_trash missing ${key}`)
    }
    assert.equal(listed.items.length, 1)
    const itemSchema = listDef.output.schema.properties.items.items
    for (const key of itemSchema.required) {
      assert.notEqual(listed.items[0][key], undefined, `list_trash item missing ${key}`)
    }
    for (const key of Object.keys(listed.items[0])) {
      assert.ok(key in itemSchema.properties, `list_trash item unexpected key ${key}`)
    }
    assert.equal(listed.items[0].session_id, 'sess-1')

    const restoreDef = tools.get('restore_file')
    const restored = await restoreDef.execute(
      { trash_id: deleted.trash_id },
      execution('restore_file', { trash_id: deleted.trash_id }, undefined, space.root, 'sess-1'),
    )
    for (const key of restoreDef.output.schema.required) {
      assert.notEqual(restored[key], undefined, `restore_file missing ${key}`)
    }
    for (const key of Object.keys(restored)) {
      assert.ok(key in restoreDef.output.schema.properties, `restore_file unexpected key ${key}`)
    }
  } finally {
    space.dispose()
  }
})
