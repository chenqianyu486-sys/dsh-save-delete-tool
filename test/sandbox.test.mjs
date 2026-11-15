// The sandbox gate: `delete_file` / `restore_file` move files with `node:fs`,
// outside the Harness filesystem fence, so they read the session's policy
// themselves instead of becoming a mutation channel the sandbox cannot close.

import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { apply } from '../index.js'
import { execution, fakeContext, workspace } from './helpers.mjs'

/**
 * Register the plugin against one workspace.
 * @returns the tool map plus the policy requests the gate made.
 */
function toolsFor(space, options) {
  const { ctx, tools, sandboxCalls } = fakeContext(space.root, options)
  apply(ctx)
  return { tools, sandboxCalls }
}

/** One `delete_file` call against a workspace. */
const deleteCall = (space, file, sessionId) =>
  execution('delete_file', { path: file }, undefined, space.root, sessionId)

test('a read-only session refuses the deletion and moves nothing', async () => {
  const space = workspace()
  try {
    const { tools, sandboxCalls } = toolsFor(space, { sandboxMode: 'read-only' })
    space.write('src/app.js', 'hello')
    await assert.rejects(
      tools.get('delete_file').execute({ path: 'src/app.js' }, deleteCall(space, 'src/app.js')),
      (error) => error?.code === 'SANDBOX_READ_ONLY' && /read-only mode/.test(error.message),
    )
    assert.equal(readFileSync(path.join(space.root, 'src/app.js'), 'utf8'), 'hello')
    assert.equal(existsSync(path.join(space.root, '.dsh', 'trash', 'items')), false)

    // The gate must read the policy for THIS call's session, not a cached mode.
    assert.equal(sandboxCalls.length, 1)
    assert.equal(sandboxCalls[0].session.header.cwd, space.root)
    assert.equal(sandboxCalls[0].session.id, 'session-test')
  } finally {
    space.dispose()
  }
})

test('a dry run and list_trash stay available in a read-only session', async () => {
  const space = workspace()
  try {
    const { tools } = toolsFor(space, { sandboxMode: 'read-only' })
    space.write('app.js', 'hello')
    const preview = await tools.get('delete_file').execute(
      { path: 'app.js', dry_run: true },
      deleteCall(space, 'app.js'),
    )
    assert.equal(preview.dry_run, true)
    assert.equal(preview.kind, 'file')
    const listed = await tools.get('list_trash').execute(
      { query: '' },
      execution('list_trash', { query: '' }, undefined, space.root),
    )
    assert.equal(listed.total, 0)
    assert.equal(existsSync(path.join(space.root, 'app.js')), true)
    assert.equal(existsSync(path.join(space.root, '.dsh')), false, 'list_trash must not create the trash')
  } finally {
    space.dispose()
  }
})

test('restoring is a mutation too, so read-only refuses it', async () => {
  const space = workspace()
  try {
    const writable = toolsFor(space, { sandboxMode: 'workspace-write' })
    space.write('a.txt', 'x')
    const deleted = await writable.tools
      .get('delete_file')
      .execute({ path: 'a.txt' }, deleteCall(space, 'a.txt'))

    const readOnly = toolsFor(space, { sandboxMode: 'read-only' })
    await assert.rejects(
      readOnly.tools.get('restore_file').execute(
        { trash_id: deleted.trash_id },
        execution('restore_file', { trash_id: deleted.trash_id }, undefined, space.root),
      ),
      (error) => error?.code === 'SANDBOX_READ_ONLY',
    )
    assert.equal(existsSync(path.join(space.root, 'a.txt')), false)
  } finally {
    space.dispose()
  }
})

test('workspace-write keeps the recoverable path working end to end', async () => {
  const space = workspace()
  try {
    const { tools } = toolsFor(space, { sandboxMode: 'workspace-write' })
    space.write('a.txt', 'x')
    const deleted = await tools
      .get('delete_file')
      .execute({ path: 'a.txt' }, deleteCall(space, 'a.txt'))
    assert.equal(deleted.ok, true)
    await tools
      .get('restore_file')
      .execute({ trash_id: deleted.trash_id }, execution('restore_file', { trash_id: deleted.trash_id }, undefined, space.root))
    assert.equal(readFileSync(path.join(space.root, 'a.txt'), 'utf8'), 'x')
  } finally {
    space.dispose()
  }
})

test('danger-full-access is not gated', async () => {
  const space = workspace()
  try {
    const { tools } = toolsFor(space, { sandboxMode: 'danger-full-access' })
    space.write('a.txt', 'x')
    const deleted = await tools
      .get('delete_file')
      .execute({ path: 'a.txt' }, deleteCall(space, 'a.txt'))
    assert.equal(deleted.ok, true)
  } finally {
    space.dispose()
  }
})

test('each session resolves its own mode', async () => {
  const space = workspace()
  try {
    const modes = { 'session-a': 'read-only', 'session-b': 'workspace-write' }
    const { tools, sandboxCalls } = toolsFor(space, {
      sandbox: (request) => ({ mode: modes[request.session.id], workspaceRoot: space.root }),
    })
    space.write('a.txt', 'x')
    space.write('b.txt', 'y')

    await assert.rejects(
      tools.get('delete_file').execute({ path: 'a.txt' }, deleteCall(space, 'a.txt', 'session-a')),
      (error) => error?.code === 'SANDBOX_READ_ONLY',
    )
    const allowed = await tools
      .get('delete_file')
      .execute({ path: 'b.txt' }, deleteCall(space, 'b.txt', 'session-b'))

    assert.equal(allowed.ok, true)
    assert.deepEqual(
      [...new Set(sandboxCalls.map((request) => request.session.id))],
      ['session-a', 'session-b'],
    )
  } finally {
    space.dispose()
  }
})

test('an agentless call resolves the deployment default, then refuses to guess a workspace', async () => {
  const space = workspace()
  try {
    const { tools, sandboxCalls } = toolsFor(space, { sandboxMode: 'workspace-write' })
    space.write('a.txt', 'x')
    const agentless = { ...deleteCall(space, 'a.txt'), agent: undefined }
    await assert.rejects(
      tools.get('delete_file').execute({ path: 'a.txt' }, agentless),
      (error) => error?.code === 'WORKSPACE_UNAVAILABLE',
    )
    assert.equal(sandboxCalls[0].session, undefined)
    assert.equal(existsSync(path.join(space.root, 'a.txt')), true)
  } finally {
    space.dispose()
  }
})

test('a policy that cannot be resolved fails closed', async () => {
  const space = workspace()
  try {
    const { tools } = toolsFor(space, {
      sandbox: () => {
        throw new Error('the session cwd is not an execution-world path')
      },
    })
    space.write('a.txt', 'x')
    await assert.rejects(
      tools.get('delete_file').execute({ path: 'a.txt' }, deleteCall(space, 'a.txt')),
      (error) =>
        error?.code === 'SANDBOX_POLICY_UNAVAILABLE' && /not an execution-world path/.test(error.message),
    )
    assert.equal(existsSync(path.join(space.root, 'a.txt')), true)
  } finally {
    space.dispose()
  }
})

test('an unknown mode and a policy without resolve() both fail closed', async () => {
  const space = workspace()
  try {
    const unknown = toolsFor(space, { sandboxMode: 'readonly' })
    space.write('a.txt', 'x')
    await assert.rejects(
      unknown.tools.get('delete_file').execute({ path: 'a.txt' }, deleteCall(space, 'a.txt')),
      (error) => error?.code === 'SANDBOX_POLICY_UNAVAILABLE',
    )

    const { ctx, tools } = fakeContext(space.root, { sandboxMode: 'workspace-write' })
    const get = ctx.get.bind(ctx)
    ctx.get = (name) => (name === 'sandboxPolicy' ? {} : get(name))
    apply(ctx)
    await assert.rejects(
      tools.get('delete_file').execute({ path: 'a.txt' }, deleteCall(space, 'a.txt')),
      (error) => error?.code === 'SANDBOX_POLICY_UNAVAILABLE',
    )
    assert.equal(existsSync(path.join(space.root, 'a.txt')), true)
  } finally {
    space.dispose()
  }
})

test('a host without the policy service keeps the previous behavior', async () => {
  const space = workspace()
  try {
    const { tools, sandboxCalls } = toolsFor(space, {})
    space.write('a.txt', 'x')
    const deleted = await tools
      .get('delete_file')
      .execute({ path: 'a.txt' }, deleteCall(space, 'a.txt'))
    assert.equal(deleted.ok, true)
    assert.equal(sandboxCalls.length, 0)
  } finally {
    space.dispose()
  }
})

test('the sandbox workspace root wins over a changed working directory', async () => {
  const space = workspace()
  const elsewhere = workspace()
  try {
    const { tools } = toolsFor(space, {
      sandboxMode: 'workspace-write',
      workingDirectoryRoot: elsewhere.root,
    })
    space.write('a.txt', 'x')
    elsewhere.write('b.txt', 'y')

    const deleted = await tools
      .get('delete_file')
      .execute({ path: 'a.txt' }, deleteCall(space, 'a.txt'))
    assert.equal(deleted.ok, true)
    assert.equal(existsSync(path.join(space.root, 'a.txt')), false)
    assert.equal(existsSync(path.join(elsewhere.root, 'b.txt')), true)
    assert.equal(existsSync(path.join(elsewhere.root, '.dsh')), false)

    const outside = path.join(elsewhere.root, 'b.txt')
    await assert.rejects(
      tools.get('delete_file').execute({ path: outside }, deleteCall(space, outside)),
      (error) => error?.code === 'PATH_OUTSIDE_WORKSPACE',
    )
    assert.equal(existsSync(outside), true)
  } finally {
    space.dispose()
    elsewhere.dispose()
  }
})
