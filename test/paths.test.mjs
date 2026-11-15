import assert from 'node:assert/strict'
import { mkdirSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { ensureSafeParent, inspectRestorePath, inspectTarget, trashRootFor } from '../lib/paths.js'
import { trySymlink, workspace } from './helpers.mjs'

function refused(fn, code) {
  assert.throws(fn, (error) => error?.code === code)
}

test('accepts a file inside the workspace', () => {
  const space = workspace()
  try {
    const absolute = space.write('src/app.js', 'x')
    const target = inspectTarget({ root: space.root, input: 'src/app.js' })
    assert.equal(target.relative, 'src/app.js')
    assert.equal(target.kind, 'file')
    assert.equal(target.absolute, absolute)
  } finally {
    space.dispose()
  }
})

test('accepts an absolute path inside the workspace', () => {
  const space = workspace()
  try {
    const absolute = space.write('a.txt', 'x')
    assert.equal(inspectTarget({ root: space.root, input: absolute }).relative, 'a.txt')
  } finally {
    space.dispose()
  }
})

test('refuses the workspace root and anything outside it', () => {
  const space = workspace()
  try {
    space.write('a.txt', 'x')
    refused(() => inspectTarget({ root: space.root, input: '.' }), 'REFUSE_WORKSPACE_ROOT')
    refused(() => inspectTarget({ root: space.root, input: '..' }), 'PATH_OUTSIDE_WORKSPACE')
    refused(() => inspectTarget({ root: space.root, input: '../../a.txt' }), 'PATH_OUTSIDE_WORKSPACE')
    refused(() => inspectTarget({ root: space.root, input: path.join(space.root, '..', 'x') }), 'PATH_OUTSIDE_WORKSPACE')
  } finally {
    space.dispose()
  }
})

test('refuses a parent directory that is a symlink out of the workspace', (t) => {
  const space = workspace()
  try {
    const outside = workspace()
    try {
      outside.write('secret.txt', 'x')
      mkdirSync(path.join(space.root, 'link'))
      if (!trySymlink(outside.root, path.join(space.root, 'link', 'escape'), 'dir')) {
        t.skip('creating symlinks needs Developer Mode or elevation on Windows')
        return
      }
      refused(() => inspectTarget({ root: space.root, input: 'link/escape/secret.txt' }), 'PATH_OUTSIDE_WORKSPACE')
    } finally {
      outside.dispose()
    }
  } finally {
    space.dispose()
  }
})

test('a symlink target is deleted as a link, not followed', (t) => {
  const outside = workspace()
  const space = workspace()
  try {
    const target = outside.write('target.txt', 'keep me')
    if (!trySymlink(target, path.join(space.root, 'link.txt'))) {
      t.skip('creating symlinks needs Developer Mode or elevation on Windows')
      return
    }
    const inspected = inspectTarget({ root: space.root, input: 'link.txt' })
    assert.equal(inspected.kind, 'symlink')
  } finally {
    space.dispose()
    outside.dispose()
  }
})

test('refuses protected segments and the trash', () => {
  const space = workspace()
  try {
    space.write('.git/config', 'x')
    space.write('.env', 'SECRET=1')
    space.write('.dsh/state.json', '{}')
    refused(() => inspectTarget({ root: space.root, input: '.git/config' }), 'PATH_PROTECTED')
    refused(() => inspectTarget({ root: space.root, input: '.env' }), 'PATH_PROTECTED')
    refused(() => inspectTarget({ root: space.root, input: '.dsh/state.json' }), 'PATH_PROTECTED')
    refused(() => inspectTarget({ root: space.root, input: '.dsh/trash/x' }), 'PATH_PROTECTED')
    assert.equal(trashRootFor(space.root), path.join(space.root, '.dsh', 'trash'))
  } finally {
    space.dispose()
  }
})

test('refuses a protected segment reached through a symlinked parent', (t) => {
  const space = workspace()
  try {
    space.write('.git/config', 'x')
    if (!trySymlink(path.join(space.root, '.git'), path.join(space.root, 'link'), 'dir')) {
      t.skip('creating symlinks needs Developer Mode or elevation on Windows')
      return
    }
    refused(() => inspectTarget({ root: space.root, input: 'link/config' }), 'PATH_PROTECTED')
    refused(() => ensureSafeParent(space.root, path.join(space.root, 'link', 'config')), 'PATH_PROTECTED')
  } finally {
    space.dispose()
  }
})

test('missing targets are refused with a stable code', () => {
  const space = workspace()
  try {
    refused(() => inspectTarget({ root: space.root, input: 'missing.txt' }), 'PATH_NOT_FOUND')
  } finally {
    space.dispose()
  }
})

test('normalizes Windows backslashes before protected-path checks', (t) => {
  if (process.platform !== 'win32') {
    t.skip('Windows path separator rule')
    return
  }
  const space = workspace()
  try {
    assert.equal(
      inspectRestorePath({ root: space.root, storedPath: 'sub\\file.txt' }),
      path.join(space.root, 'sub', 'file.txt'),
    )
    refused(() => inspectRestorePath({ root: space.root, storedPath: 'sub\\.git\\payload.txt' }), 'PATH_PROTECTED')
  } finally {
    space.dispose()
  }
})

test('restore paths are data and are re-validated', () => {
  const space = workspace()
  try {
    refused(() => inspectRestorePath({ root: space.root, storedPath: '../x' }), 'TRASH_RECORD_CORRUPT')
    refused(() => inspectRestorePath({ root: space.root, storedPath: 'C:/x' }), 'TRASH_RECORD_CORRUPT')
    refused(() => inspectRestorePath({ root: space.root, storedPath: '/x' }), 'TRASH_RECORD_CORRUPT')
    refused(() => inspectRestorePath({ root: space.root, storedPath: '.git/config' }), 'PATH_PROTECTED')
    assert.equal(
      inspectRestorePath({ root: space.root, storedPath: 'src/app.js' }),
      path.join(space.root, 'src', 'app.js'),
    )
  } finally {
    space.dispose()
  }
})

test('ensureSafeParent creates missing directories and refuses an escaping symlink', (t) => {
  const space = workspace()
  try {
    const destination = path.join(space.root, 'a', 'b', 'c.txt')
    ensureSafeParent(space.root, destination)
    assert.ok(inspectTarget({ root: space.root, input: 'a/b' }))
  } finally {
    space.dispose()
  }

  const outside = workspace()
  const second = workspace()
  try {
    mkdirSync(path.join(second.root, 'node_modules'))
    if (!trySymlink(outside.root, path.join(second.root, 'node_modules', 'escape'), 'dir')) {
      t.skip('creating symlinks needs Developer Mode or elevation on Windows')
      return
    }
    refused(
      () => ensureSafeParent(second.root, path.join(second.root, 'node_modules', 'escape', 'x.txt')),
      'PATH_OUTSIDE_WORKSPACE',
    )
  } finally {
    second.dispose()
    outside.dispose()
  }
})
