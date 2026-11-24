import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { apply } from '../index.js'
import { analyzeExecution } from '../lib/guard.js'
import { execution, fakeContext, objectSchema, trySymlink, workspace } from './helpers.mjs'

const pwshSchema = objectSchema({ command: { type: 'string' }, description: { type: 'string' } })
const codeSchema = objectSchema({ code: { type: 'string' }, description: { type: 'string' } })

test('classifies the four presets by schema shape', () => {
  const cases = [
    ['standard', 'pwsh', pwshSchema, { command: 'rm -rf build', description: 'cleanup' }, true],
    ['ptc', 'run_code', codeSchema, { code: 'const fs = await import("node:fs"); fs.rmSync(dir)', description: 'x' }, true],
    ['minimal', 'pwsh', objectSchema({ command: { type: 'string' } }), { command: 'Remove-Item -Recurse build' }, true],
    ['cordis', 'cordis_inspect_query', objectSchema({}), {}, false],
  ]
  for (const [mode, name, schema, args, denied] of cases) {
    const result = analyzeExecution(execution(name, args, schema, process.cwd()), undefined)
    assert.equal(result !== null, denied, `${mode}: ${JSON.stringify(result)}`)
  }
})

test('classifies by schema, not by tool name', () => {
  const schema = objectSchema({ command: { type: 'string' } })
  assert.notEqual(analyzeExecution(execution('some_shell', { command: 'rm -rf x' }, schema, process.cwd()), undefined), null)
  assert.equal(analyzeExecution(execution('some_tool', { text: 'rm -rf x' }, objectSchema({ text: { type: 'string' } }), process.cwd()), undefined), null)
})

test('covers the optional terminal-input shape without classifying workflow scripts', () => {
  const terminal = objectSchema({
    sessionId: { type: 'string' },
    text: { type: 'string' },
    submit: { type: 'boolean' },
  })
  const terminalHit = analyzeExecution(
    execution('terminal_send', { sessionId: 't1', text: 'rm -rf build', submit: true }, terminal, process.cwd()),
    undefined,
  )
  assert.equal(terminalHit?.channel, 'terminal')
  assert.equal(terminalHit?.code, 'SHELL_DELETE')

  const workflow = objectSchema({ script: { type: 'string' }, description: { type: 'string' } })
  const script = 'const prompt = "rm -rf build"; await agent(prompt)'
  assert.equal(
    analyzeExecution(execution('workflow', { script, description: 'x' }, workflow, process.cwd()), undefined),
    null,
  )
})

test('refuses a native patch delete', () => {
  const schema = objectSchema({ input: { type: 'string' } })
  const deleted = analyzeExecution(
    execution('apply_patch', { input: '*** Begin Patch\n*** Delete File: src/old.js\n*** End Patch' }, schema, process.cwd()),
    undefined,
  )
  assert.equal(deleted?.channel, 'patch')
  assert.equal(deleted?.code, 'PATCH_DELETE')

  const added = analyzeExecution(
    execution('apply_patch', { input: '*** Begin Patch\n*** Add File: src/new.js\n+hello\n*** End Patch' }, schema, process.cwd()),
    undefined,
  )
  assert.equal(added, null)

  const contextOnly = analyzeExecution(
    execution(
      'apply_patch',
      { input: '*** Begin Patch\n*** Update File: README.md\n@@\n *** Delete File: src/old.js\n+updated\n*** End Patch' },
      schema,
      process.cwd(),
    ),
    undefined,
  )
  assert.equal(contextOnly, null)

  const patchParam = analyzeExecution(
    execution(
      'apply_patch',
      { patch: '*** Begin Patch\n*** Delete File: src/old.js\n*** End Patch' },
      objectSchema({ patch: { type: 'string' } }),
      process.cwd(),
    ),
    undefined,
  )
  assert.equal(patchParam?.code, 'PATCH_DELETE')
})

test('scans every payload of a shell tool, not only `command`', () => {
  const schema = objectSchema({ command: { type: 'string' }, stdin: { type: 'string' } })
  const result = analyzeExecution(
    execution('wsl', { command: 'bash', stdin: 'rm -rf build' }, schema, process.cwd()),
    undefined,
  )
  assert.equal(result?.code, 'SHELL_DELETE')
})

test('ignores metadata prose', () => {
  const result = analyzeExecution(
    execution('pwsh', { command: 'echo hi', description: 'rm -rf build' }, pwshSchema, process.cwd()),
    undefined,
  )
  assert.equal(result, null)
})

test('does not analyze the delete tool itself', () => {
  const schema = objectSchema({ path: { type: 'string' } })
  assert.equal(analyzeExecution(execution('delete_file', { path: 'rm -rf build' }, schema, process.cwd()), undefined), null)
})

test('falls back to known names when the schema is absent', () => {
  assert.notEqual(analyzeExecution(execution('wsl-term', { command: 'rm -rf x' }, undefined, process.cwd()), undefined), null)
  assert.notEqual(analyzeExecution(execution('run_code', { code: 'fs.rmSync(x)' }, undefined, process.cwd()), undefined), null)
})

test('the plugin registers three tools, one guard and one prompt section', async () => {
  const space = workspace()
  try {
    const { ctx, tools, guards, preExecute, sections } = fakeContext(space.root)
    apply(ctx)
    assert.deepEqual([...tools.keys()].sort(), ['delete_file', 'list_trash', 'restore_file'])
    assert.equal(guards.length, 1)
    assert.equal(preExecute.length, 1)
    assert.equal(sections.length, 1)
    assert.equal(sections[0].name, 'safe-delete')

    const exec = execution('pwsh', { command: 'rm -rf build' }, pwshSchema, space.root)
    const guardResult = guards[0](exec)
    assert.match(guardResult.reason, /Blocked an irreversible shell deletion/)
    assert.equal(guardResult.info.code, 'SHELL_DELETE')

    const allowed = await preExecute[0](
      execution('pwsh', { command: 'echo hi' }, pwshSchema, space.root),
      async () => ({ kind: 'allow' }),
    )
    assert.equal(allowed.kind, 'allow')

    const denied = await preExecute[0](exec, async () => ({ kind: 'allow' }))
    assert.equal(denied.kind, 'deny')

    const asked = await preExecute[0](exec, async () => ({ kind: 'ask', reason: 'other plugin' }))
    assert.equal(asked.kind, 'deny', 'a recognized deletion is denied before approval, even when another listener asks')

    const safeAsk = { kind: 'ask', reason: 'other plugin' }
    assert.equal(
      await preExecute[0](
        execution('pwsh', { command: 'echo hi' }, pwshSchema, space.root),
        async () => safeAsk,
      ),
      safeAsk,
      'a non-deletion keeps the other listener\'s ask',
    )
  } finally {
    space.dispose()
  }
})

test('delete, list and restore work end to end through the tool definitions', async () => {
  const space = workspace()
  try {
    const { ctx, tools } = fakeContext(space.root)
    apply(ctx)
    space.write('src/app.js', 'hello')

    const deleted = await tools.get('delete_file').execute(
      { path: 'src/app.js', reason: 'test' },
      execution('delete_file', { path: 'src/app.js', reason: 'test' }, undefined, space.root),
    )
    assert.equal(deleted.ok, true)
    assert.match(deleted.trash_id, /^\d{8}T\d{9}-[0-9a-f]{8}$/)

    const listed = await tools.get('list_trash').execute(
      { query: '' },
      execution('list_trash', { query: '' }, undefined, space.root),
    )
    assert.equal(listed.items.length, 1)

    const restored = await tools.get('restore_file').execute(
      { trash_id: deleted.trash_id },
      execution('restore_file', { trash_id: deleted.trash_id }, undefined, space.root),
    )
    assert.equal(restored.ok, true)
    assert.equal(readFileSync(path.join(space.root, 'src/app.js'), 'utf8'), 'hello')
  } finally {
    space.dispose()
  }
})

test('restore through the tool refuses an external item junction', async (t) => {
  const space = workspace()
  const outside = workspace()
  const id = '20260101T000000-deadbeef'
  try {
    const items = path.join(space.root, '.dsh', 'trash', 'items')
    mkdirSync(items, { recursive: true })
    outside.write('payload', 'outside secret')
    writeFileSync(
      path.join(outside.root, 'meta.json'),
      JSON.stringify({
        version: 1,
        id,
        path: 'stolen.txt',
        kind: 'file',
        entries: 0,
        reason: 'junction probe',
        sessionId: '',
        deletedAt: '2026-01-01T00:00:00.000Z',
        status: 'trashed',
      }),
    )
    if (!trySymlink(outside.root, path.join(items, id), 'dir')) {
      t.skip('creating symlinks needs Developer Mode or elevation on Windows')
      return
    }

    const { ctx, tools } = fakeContext(space.root, { sandboxMode: 'workspace-write' })
    apply(ctx)
    await assert.rejects(
      tools.get('restore_file').execute(
        { trash_id: id },
        execution('restore_file', { trash_id: id }, undefined, space.root),
      ),
      (error) => error?.code === 'TRASH_ITEM_OUTSIDE_WORKSPACE',
    )
    assert.equal(existsSync(path.join(space.root, 'stolen.txt')), false)
    assert.equal(existsSync(path.join(outside.root, 'payload')), true)
  } finally {
    space.dispose()
    outside.dispose()
  }
})

test('a non-recursive directory delete is refused through the tool', async () => {
  const space = workspace()
  try {
    const { ctx, tools } = fakeContext(space.root)
    apply(ctx)
    space.write('build/a.txt', 'x')
    await assert.rejects(
      tools.get('delete_file').execute(
        { path: 'build' },
        execution('delete_file', { path: 'build' }, undefined, space.root),
      ),
      (error) => error?.code === 'RECURSIVE_FLAG_REQUIRED',
    )
  } finally {
    space.dispose()
  }
})

test('ignores terminal sessionId metadata and supports anyOf schema parameters', () => {
  const terminal = objectSchema({
    sessionId: { type: 'string' },
    text: { type: 'string' },
    submit: { type: 'boolean' },
  })
  assert.equal(
    analyzeExecution(
      execution('terminal_send', { sessionId: 'rm', text: 'ls', submit: true }, terminal, process.cwd()),
      undefined,
    ),
    null,
  )

  const anyOfShell = objectSchema({
    command: { anyOf: [{ type: 'string' }, { type: 'null' }] },
  })
  assert.equal(
    analyzeExecution(execution('custom_shell', { command: 'rm -rf build' }, anyOfShell, process.cwd()), undefined)?.code,
    'SHELL_DELETE',
  )
})

test('reports PROGRAM_TOO_LONG as uninspectable and preserves query/limit in list_trash next-page hint', () => {
  const space = workspace()
  try {
    const { ctx, tools, guards } = fakeContext(space.root)
    apply(ctx)
    const denied = guards[0](
      execution('run_code', { code: `const x = 1; ${'x'.repeat(70_000)}` }, codeSchema, space.root),
    )
    assert.equal(denied?.info?.code, 'PROGRAM_TOO_LONG')
    assert.match(denied.reason, /Blocked a program call the guard could not inspect/)

    const rendered = tools.get('list_trash').output.render(
      { query: 'src', limit: 2, offset: 0 },
      {
        items: [
          { trash_id: 'id-1', path: 'src/a.js', kind: 'file', entries: 0, deleted_at: '2026-01-01T00:00:00.000Z', reason: '' },
          { trash_id: 'id-2', path: 'src/b.js', kind: 'file', entries: 0, deleted_at: '2026-01-01T00:00:00.000Z', reason: '' },
        ],
        total: 5,
        trash_total: 5,
        offset: 0,
      },
    )
    assert.match(rendered[0].text, /list_trash\(\{"query":"src","limit":2,"offset":2\}\)/)
  } finally {
    space.dispose()
  }
})
