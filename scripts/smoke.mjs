import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { apply, inject, name, VERSION } from '../index.js'
import { TrashStore, movePath } from '../lib/trash.js'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function createHarnessContext(root, sandboxMode = 'workspace-write') {
  const tools = new Map()
  const guards = []
  const preExecute = []
  const sections = []
  const services = {
    sandboxPolicy: {
      resolve() {
        return { mode: sandboxMode, workspaceRoot: root }
      },
    },
    workingDirectory: {
      async ensure() {
        return root
      },
      get() {
        return root
      },
    },
  }
  const ctx = {
    tools: {
      register(definition) {
        tools.set(definition.name, definition)
        return () => tools.delete(definition.name)
      },
      guard(callback) {
        guards.push(callback)
        return () => {}
      },
      get(toolName) {
        return tools.get(toolName)
      },
    },
    get(serviceName) {
      return services[serviceName]
    },
    on(event, callback) {
      if (event === 'tools/pre-execute') preExecute.push(callback)
      return () => {}
    },
    effect(callback) {
      const dispose = callback()
      return typeof dispose === 'function' ? dispose : () => {}
    },
    inject(_deps, callback) {
      callback({
        systemPrompt: {
          section(section) {
            sections.push(section)
            return () => {}
          },
        },
        effect: ctx.effect,
      })
    },
  }
  return { ctx, tools, guards, preExecute, sections }
}

function makeExec(toolName, args, parameters, root, sessionId = 'smoke-session') {
  return {
    name: toolName,
    arguments: args,
    schema: parameters === undefined ? undefined : { name: toolName, description: '', parameters },
    signal: new AbortController().signal,
    agent: {
      id: 'smoke-agent',
      session: { id: sessionId, header: { cwd: root } },
    },
  }
}

async function run() {
  const checks = []
  const record = (label) => checks.push(label)

  // 1. Bundle manifest & static assets
  assert.equal(name, 'safe-delete')
  assert.deepEqual(inject, ['tools'])
  const pkgBytes = readFileSync(path.join(repoRoot, 'package.json'))
  assert.equal(pkgBytes[0], 0x7b, 'package.json must not start with a UTF-8 BOM')
  const pkg = JSON.parse(pkgBytes.toString('utf8'))
  assert.equal(pkg.version, VERSION)
  const patch = readFileSync(path.join(repoRoot, 'cordis.patch.yml'), 'utf8')
  assert.match(patch, /id: safe-delete/)
  for (const locale of ['locale/en.json', 'locale/zh.json']) {
    const bytes = readFileSync(path.join(repoRoot, locale))
    assert.notEqual(bytes[0], 0xef, `${locale} must not have a BOM`)
    const data = JSON.parse(bytes.toString('utf8'))
    assert.ok(data.meta?.title && data.meta?.description)
  }
  assert.match(readFileSync(path.join(repoRoot, 'icon.svg'), 'utf8').trim(), /^<svg[\s>]/)
  record('bundle manifest, patch, locales, icon')

  const space = mkdtempSync(path.join(tmpdir(), 'dsh-safe-delete-smoke-'))
  try {
    // 2. Mount plugin and verify four presets + versioned refusal
    const { ctx, tools, guards, preExecute, sections } = createHarnessContext(space, 'workspace-write')
    apply(ctx)
    assert.deepEqual([...tools.keys()].sort(), ['delete_file', 'list_trash', 'restore_file'])
    assert.equal(guards.length, 1)
    assert.equal(preExecute.length, 1)
    assert.equal(sections.length, 1)

    const shellSchema = { type: 'object', properties: { command: { type: 'string' }, description: { type: 'string' } } }
    const codeSchema = { type: 'object', properties: { code: { type: 'string' } } }
    const cordisSchema = { type: 'object', properties: {} }

    const shellDeny = guards[0](makeExec('pwsh', { command: 'Remove-Item -Recurse build' }, shellSchema, space))
    assert.ok(shellDeny && shellDeny.reason.includes(`[dsh-safe-delete-tool v${VERSION}]`))
    const ptcDeny = guards[0](makeExec('run_code', { code: 'await pwsh({ command: "Remove-Item x" })' }, codeSchema, space))
    assert.equal(ptcDeny?.info?.code, 'PROGRAM_SHELL_DELETE')
    const minimalDeny = await preExecute[0](
      makeExec('pwsh', { command: 'rm -rf build' }, { type: 'object', properties: { command: { type: 'string' } } }, space),
      async () => ({ kind: 'ask' }),
    )
    assert.equal(minimalDeny.kind, 'deny')
    assert.equal(guards[0](makeExec('cordis_inspect_query', {}, cordisSchema, space)), undefined)
    record('four presets and versioned refusal')

    // 3. Harmless rm mention allowed
    for (const cmd of ['git commit -m "rm old"', 'echo "rm -rf"']) {
      const exec = makeExec('pwsh', { command: cmd }, shellSchema, space)
      assert.equal(guards[0](exec), undefined)
      const pre = await preExecute[0](exec, async () => ({ kind: 'allow' }))
      assert.equal(pre.kind, 'allow')
    }
    record('harmless rm mentions allowed')

    // 4. Delete -> List -> Restore -> Overwrite round-trip
    const targetFile = path.join(space, 'scratch.txt')
    writeFileSync(targetFile, 'original')
    const deleted = await tools.get('delete_file').execute(
      { path: 'scratch.txt', reason: 'smoke test' },
      makeExec('delete_file', { path: 'scratch.txt' }, undefined, space),
    )
    assert.equal(deleted.ok, true)
    assert.equal(existsSync(targetFile), false)

    const listed = await tools.get('list_trash').execute(
      { trash_id: deleted.trash_id },
      makeExec('list_trash', { trash_id: deleted.trash_id }, undefined, space),
    )
    assert.equal(listed.items.length, 1)
    assert.equal(listed.items[0].trash_id, deleted.trash_id)

    writeFileSync(targetFile, 'occupant')
    const restored = await tools.get('restore_file').execute(
      { trash_id: deleted.trash_id, overwrite: true },
      makeExec('restore_file', { trash_id: deleted.trash_id, overwrite: true }, undefined, space),
    )
    assert.equal(restored.ok, true)
    assert.equal(readFileSync(targetFile, 'utf8'), 'original')
    assert.ok(restored.replaced_trash_id)
    record('delete -> list -> restore with overwrite')

    // 5. Read-only sandbox gate
    const ro = createHarnessContext(space, 'read-only')
    apply(ro.ctx)
    await assert.rejects(
      ro.tools.get('delete_file').execute({ path: 'scratch.txt' }, makeExec('delete_file', { path: 'scratch.txt' }, undefined, space)),
      (err) => err?.code === 'SANDBOX_READ_ONLY',
    )
    record('read-only sandbox refusal')

    // 6. Windows ADS / 8.3 / trailing-dot refusal
    if (process.platform === 'win32') {
      mkdirSync(path.join(space, '.git'), { recursive: true })
      writeFileSync(path.join(space, '.git', 'config'), 'x')
      for (const bad of ['GIT~1', '.git::$INDEX_ALLOCATION', '.git.']) {
        await assert.rejects(
          tools.get('delete_file').execute({ path: bad }, makeExec('delete_file', { path: bad }, undefined, space)),
          (err) => err?.code === 'PATH_ALIAS_UNSUPPORTED',
        )
      }
      record('Windows ADS / 8.3 / trailing-dot alias refusal')
    }

    // 7. 1.x migration failure retry in an isolated subdir
    const legacySpace = path.join(space, 'legacy-ws')
    const legacyItems = path.join(legacySpace, '.dsh', 'trash', 'items')
    mkdirSync(legacyItems, { recursive: true })
    const oldId = '20260101T000000-abcdef12'
    writeFileSync(path.join(legacyItems, `${oldId}__old.txt`), 'legacy-smoke')
    writeFileSync(
      path.join(legacySpace, '.dsh', 'trash', 'manifest.json'),
      JSON.stringify({
        version: 1,
        items: [
          {
            id: oldId,
            originalRelPath: 'old.txt',
            trashRelPath: `items/${oldId}__old.txt`,
            kind: 'file',
            deletedAt: '2026-01-01T00:00:00.000Z',
            reason: 'smoke',
            state: 'trashed',
          },
        ],
      }),
    )
    let failFirst = true
    const legacyStore = new TrashStore({
      root: legacySpace,
      move(src, dst) {
        if (failFirst) {
          failFirst = false
          throw Object.assign(new Error('simulated EACCES'), { code: 'EACCES' })
        }
        movePath(src, dst)
      },
    })
    assert.throws(() => legacyStore.restore(oldId, { overwrite: false }), (err) => err?.code === 'TRASH_ITEM_NOT_FOUND')
    assert.equal(legacyStore.list({ query: '', trashId: '', limit: 10, offset: 0 }).items.length, 1)
    legacyStore.restore(oldId, { overwrite: false })
    assert.equal(readFileSync(path.join(legacySpace, 'old.txt'), 'utf8'), 'legacy-smoke')
    record('1.x migration failure retry')

    // 8. Dangling symlink round-trip (best-effort when OS permits symlinks)
    const linkTarget = path.join(space, 'gone-target')
    const linkPath = path.join(space, 'dangling-link')
    let symlinkCreated = false
    try {
      mkdirSync(linkTarget)
      symlinkSync(linkTarget, linkPath, 'dir')
      rmSync(linkTarget, { recursive: true, force: true })
      symlinkCreated = true
    } catch (error) {
      if (error?.code !== 'EPERM' && error?.code !== 'EACCES' && error?.code !== 'UNKNOWN') throw error
    }
    if (symlinkCreated) {
      const delLink = await tools.get('delete_file').execute(
        { path: 'dangling-link' },
        makeExec('delete_file', { path: 'dangling-link' }, undefined, space),
      )
      assert.equal(delLink.kind, 'symlink')
      await tools.get('restore_file').execute(
        { trash_id: delLink.trash_id },
        makeExec('restore_file', { trash_id: delLink.trash_id }, undefined, space),
      )
      record('dangling symlink round-trip')
    } else {
      record('dangling symlink round-trip (skipped: symlink privilege unavailable)')
    }
  } finally {
    rmSync(space, { recursive: true, force: true })
  }

  console.log(`smoke ok (dsh-safe-delete-tool v${VERSION}): ${checks.join('; ')}`)
}

run().catch((error) => {
  console.error(error)
  process.exit(1)
})
