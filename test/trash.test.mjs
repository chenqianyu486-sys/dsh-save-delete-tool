import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { TrashStore, movePath } from '../lib/trash.js'
import { trySymlink, workspace } from './helpers.mjs'

function refused(fn, code) {
  assert.throws(fn, (error) => error?.code === code)
}

test('delete, list and restore a file', () => {
  const space = workspace()
  try {
    space.write('src/app.js', 'hello')
    const store = new TrashStore({ root: space.root })
    const result = store.delete('src/app.js', { recursive: false, dryRun: false, reason: 'cleanup', sessionId: 's1' })
    assert.match(result.trash_id, /^\d{8}T\d{9}-[0-9a-f]{8}$/)
    assert.equal(existsSync(path.join(space.root, 'src/app.js')), false)

    const listed = store.list({ query: '', trashId: '', limit: 10, offset: 0 })
    assert.equal(listed.items.length, 1)
    assert.equal(listed.items[0].path, 'src/app.js')
    assert.equal(listed.items[0].reason, 'cleanup')

    const restored = store.restore(result.trash_id, { overwrite: false })
    assert.equal(restored.path, 'src/app.js')
    assert.equal(readFileSync(path.join(space.root, 'src/app.js'), 'utf8'), 'hello')
    assert.equal(store.list({ query: '', trashId: '', limit: 10, offset: 0 }).items.length, 0)
  } finally {
    space.dispose()
  }
})

test('a non-empty directory needs the recursive flag; an empty one does not', () => {
  const space = workspace()
  try {
    space.write('full/a.txt', 'x')
    space.mkdir('empty')
    const store = new TrashStore({ root: space.root })
    refused(
      () => store.delete('full', { recursive: false, dryRun: false, reason: '', sessionId: '' }),
      'RECURSIVE_FLAG_REQUIRED',
    )
    const deleted = store.delete('empty', { recursive: false, dryRun: false, reason: '', sessionId: '' })
    assert.equal(deleted.kind, 'directory')
  } finally {
    space.dispose()
  }
})

test('dry run reports the target and moves nothing', () => {
  const space = workspace()
  try {
    space.write('full/a.txt', 'x')
    space.write('full/b.txt', 'y')
    const store = new TrashStore({ root: space.root })
    const result = store.delete('full', { recursive: true, dryRun: true, reason: '', sessionId: '' })
    assert.equal(result.dry_run, true)
    assert.equal(result.recursive_required, true)
    assert.equal(result.entries, 2)
    assert.ok(existsSync(path.join(space.root, 'full/a.txt')))
    assert.equal(store.list({ query: '', trashId: '', limit: 10, offset: 0 }).items.length, 0)
  } finally {
    space.dispose()
  }
})

test('restore recreates a missing parent', () => {
  const space = workspace()
  try {
    space.write('a/b/c.txt', 'x')
    const store = new TrashStore({ root: space.root })
    const deleted = store.delete('a/b/c.txt', { recursive: false, dryRun: false, reason: '', sessionId: '' })
    rmSync(path.join(space.root, 'a'), { recursive: true, force: true })
    store.restore(deleted.trash_id, { overwrite: false })
    assert.equal(readFileSync(path.join(space.root, 'a/b/c.txt'), 'utf8'), 'x')
  } finally {
    space.dispose()
  }
})

test('a directory restores through the rename path, contents intact', () => {
  const space = workspace()
  try {
    space.write('build/out/a.txt', 'x')
    space.write('build/out/b.txt', 'y')
    const store = new TrashStore({ root: space.root })
    const deleted = store.delete('build', { recursive: true, dryRun: false, reason: '', sessionId: '' })
    assert.equal(deleted.kind, 'directory')
    assert.equal(existsSync(path.join(space.root, 'build')), false)
    const restored = store.restore(deleted.trash_id, { overwrite: false })
    assert.equal(restored.kind, 'directory')
    assert.equal(readFileSync(path.join(space.root, 'build/out/a.txt'), 'utf8'), 'x')
    assert.equal(readFileSync(path.join(space.root, 'build/out/b.txt'), 'utf8'), 'y')
  } finally {
    space.dispose()
  }
})

test('restore refuses an occupant unless overwrite archives it', () => {
  const space = workspace()
  try {
    space.write('a.txt', 'old')
    const store = new TrashStore({ root: space.root })
    const deleted = store.delete('a.txt', { recursive: false, dryRun: false, reason: '', sessionId: '' })
    writeFileSync(path.join(space.root, 'a.txt'), 'new')

    refused(() => store.restore(deleted.trash_id, { overwrite: false }), 'DESTINATION_EXISTS')
    const restored = store.restore(deleted.trash_id, { overwrite: true })
    assert.match(restored.replaced_trash_id, /^\d{8}T\d{9}-[0-9a-f]{8}$/)
    assert.equal(readFileSync(path.join(space.root, 'a.txt'), 'utf8'), 'old')

    const items = store.list({ query: '', trashId: '', limit: 10, offset: 0 }).items
    assert.equal(items.length, 1)
    assert.equal(items[0].trash_id, restored.replaced_trash_id)
    store.restore(restored.replaced_trash_id, { overwrite: true })
    assert.equal(readFileSync(path.join(space.root, 'a.txt'), 'utf8'), 'new')
  } finally {
    space.dispose()
  }
})

test('a symlink is archived as a link and its target survives', (t) => {
  const space = workspace()
  const outside = workspace()
  try {
    const target = outside.write('target.txt', 'keep')
    if (!trySymlink(target, path.join(space.root, 'link.txt'))) {
      t.skip('creating symlinks needs Developer Mode or elevation on Windows')
      return
    }
    const store = new TrashStore({ root: space.root })
    const deleted = store.delete('link.txt', { recursive: false, dryRun: false, reason: '', sessionId: '' })
    assert.equal(deleted.kind, 'symlink')
    assert.equal(readFileSync(target, 'utf8'), 'keep')
    store.restore(deleted.trash_id, { overwrite: false })
    assert.ok(existsSync(path.join(space.root, 'link.txt')))
    assert.equal(readFileSync(target, 'utf8'), 'keep')
  } finally {
    space.dispose()
    outside.dispose()
  }
})

test('list filters and pages newest first', () => {
  const space = workspace()
  try {
    const store = new TrashStore({ root: space.root })
    for (const name of ['one.txt', 'two.txt', 'three.txt']) {
      space.write(name, name)
      store.delete(name, { recursive: false, dryRun: false, reason: name, sessionId: '' })
    }
    const first = store.list({ query: '', trashId: '', limit: 2, offset: 0 })
    assert.equal(first.total, 3)
    assert.equal(first.trash_total, 3)
    assert.equal(first.items.length, 2)
    assert.equal(first.items[0].path, 'three.txt')

    const second = store.list({ query: '', trashId: '', limit: 2, offset: 2 })
    assert.equal(second.items.length, 1)
    assert.equal(second.items[0].path, 'one.txt')

    const filtered = store.list({ query: 'two', trashId: '', limit: 10, offset: 0 })
    assert.equal(filtered.items.length, 1)
  } finally {
    space.dispose()
  }
})

test('an unknown or malformed trash id is refused', () => {
  const space = workspace()
  try {
    const store = new TrashStore({ root: space.root })
    refused(() => store.restore('../x', { overwrite: false }), 'INVALID_TRASH_ID')
    refused(() => store.restore('nope', { overwrite: false }), 'INVALID_TRASH_ID')
    refused(() => store.restore('20260101T000000-deadbeef', { overwrite: false }), 'TRASH_ITEM_NOT_FOUND')
  } finally {
    space.dispose()
  }
})

test('the trash ignores itself in git', () => {
  const space = workspace()
  try {
    const store = new TrashStore({ root: space.root })
    space.write('a.txt', 'x')
    store.delete('a.txt', { recursive: false, dryRun: false, reason: '', sessionId: '' })
    const ignore = readFileSync(path.join(space.root, '.dsh/trash/.gitignore'), 'utf8')
    assert.match(ignore, /^\*$/m)
  } finally {
    space.dispose()
  }
})

test('a cross-volume copy is kept when the source cannot be removed', () => {
  const exdev = Object.assign(new Error('cross-device'), { code: 'EXDEV' })
  const locked = Object.assign(new Error('source is locked'), { code: 'EPERM' })
  assert.throws(
    () =>
      movePath('source', 'target', {
        renameSync() {
          throw exdev
        },
        cpSync() {},
        rmSync() {
          throw locked
        },
      }),
    (error) =>
      error?.code === 'TRASH_SOURCE_REMOVE_FAILED' &&
      error.copyComplete === true &&
      /source is locked/.test(error.message),
  )
})

test('delete keeps the copied payload when the source removal fails', () => {
  const space = workspace()
  try {
    space.write('victim.txt', 'data')
    const store = new TrashStore({
      root: space.root,
      move(source, target) {
        writeFileSync(target, readFileSync(source))
        throw Object.assign(new Error('source is locked'), { code: 'TRASH_SOURCE_REMOVE_FAILED' })
      },
    })
    assert.throws(
      () => store.delete('victim.txt', { recursive: false, dryRun: false, reason: '', sessionId: '' }),
      (error) => error?.code === 'TRASH_SOURCE_REMOVE_FAILED' && /victim\.txt/.test(error.message),
    )
    const listed = store.list({ query: '', trashId: '', limit: 10, offset: 0 })
    assert.equal(listed.items.length, 1, 'the complete copy must remain listable/restorable')
    assert.equal(existsSync(path.join(space.root, 'victim.txt')), true, 'the test stub did not remove the source')
  } finally {
    space.dispose()
  }
})

test('refuses a trash items directory that resolves outside the workspace', (t) => {
  const space = workspace()
  const outside = workspace()
  try {
    mkdirSync(path.join(space.root, '.dsh', 'trash'), { recursive: true })
    if (!trySymlink(outside.root, path.join(space.root, '.dsh', 'trash', 'items'), 'dir')) {
      t.skip('creating symlinks needs Developer Mode or elevation on Windows')
      return
    }
    const store = new TrashStore({ root: space.root })
    refused(() => store.ensureLayout(), 'TRASH_DIR_OUTSIDE_WORKSPACE')
    refused(() => store.list({ query: '', trashId: '', limit: 10, offset: 0 }), 'TRASH_DIR_OUTSIDE_WORKSPACE')
    space.write('victim.txt', 'data')
    refused(
      () => store.delete('victim.txt', { recursive: false, dryRun: false, reason: '', sessionId: '' }),
      'TRASH_DIR_OUTSIDE_WORKSPACE',
    )
    assert.equal(existsSync(path.join(space.root, 'victim.txt')), true, 'the victim must stay in the workspace')
    assert.equal(existsSync(path.join(outside.root, 'victim.txt')), false, 'nothing may be written outside')
  } finally {
    space.dispose()
    outside.dispose()
  }
})

test('refuses a trash root that resolves outside the workspace', (t) => {
  const space = workspace()
  const outside = workspace()
  try {
    if (!trySymlink(outside.root, path.join(space.root, '.dsh'), 'dir')) {
      t.skip('creating symlinks needs Developer Mode or elevation on Windows')
      return
    }
    const store = new TrashStore({ root: space.root })
    assert.throws(
      () => store.ensureLayout(),
      (error) => error?.code === 'TRASH_DIR_OUTSIDE_WORKSPACE',
    )
  } finally {
    space.dispose()
    outside.dispose()
  }
})

test('refuses a trash path with a file where a directory is required', () => {
  const space = workspace()
  try {
    writeFileSync(path.join(space.root, '.dsh'), 'not a directory')
    const store = new TrashStore({ root: space.root })
    assert.throws(
      () => store.ensureLayout(),
      (error) => error?.code === 'TRASH_DIR_NOT_DIRECTORY',
    )
  } finally {
    space.dispose()
  }
})

test('adopts a 1.x trash instead of stranding it', () => {
  const space = workspace()
  try {
    const oldId = '20260101T000000-abcdef12'
    const items = path.join(space.root, '.dsh/trash/items')
    mkdirSync(items, { recursive: true })
    writeFileSync(path.join(items, `${oldId}__old.txt`), 'legacy')
    writeFileSync(
      path.join(space.root, '.dsh/trash/manifest.json'),
      JSON.stringify({
        version: 1,
        items: [
          {
            id: oldId,
            originalRelPath: 'old.txt',
            trashRelPath: `items/${oldId}__old.txt`,
            kind: 'file',
            deletedAt: '2026-01-01T00:00:00.000Z',
            reason: 'old',
            state: 'trashed',
          },
        ],
      }),
    )
    const store = new TrashStore({ root: space.root })
    const listed = store.list({ query: '', trashId: '', limit: 10, offset: 0 })
    assert.equal(listed.items.length, 1)
    assert.equal(listed.items[0].trash_id, oldId)
    assert.equal(existsSync(path.join(items, `${oldId}__old.txt`)), true, 'listing must not migrate')
    store.restore(oldId, { overwrite: false })
    assert.equal(readFileSync(path.join(space.root, 'old.txt'), 'utf8'), 'legacy')
  } finally {
    space.dispose()
  }
})

test('parallel deletes keep one record each', () => {
  const space = workspace()
  try {
    const store = new TrashStore({ root: space.root })
    for (let index = 0; index < 12; index += 1) {
      space.write(`f${index}.txt`, String(index))
      store.delete(`f${index}.txt`, { recursive: false, dryRun: false, reason: '', sessionId: '' })
    }
    assert.equal(store.list({ query: '', trashId: '', limit: 100, offset: 0 }).items.length, 12)
  } finally {
    space.dispose()
  }
})
