import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function read(relative) {
  return readFileSync(path.join(root, relative), 'utf8')
}

test('package.json is strict JSON without a BOM', () => {
  const bytes = readFileSync(path.join(root, 'package.json'))
  assert.equal(bytes[0], 0x7b, 'package.json must start with `{`, not a UTF-8 BOM')
  const manifest = JSON.parse(bytes.toString('utf8'))
  assert.equal(manifest.name, 'dsh-safe-delete-tool')
  assert.equal(manifest.type, 'module')
  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
  assert.ok(manifest.engines.dsh)
  assert.ok(manifest.files.includes('index.js'))
  assert.ok(manifest.files.includes('lib'))
})

test('the bundle patch inserts this module', () => {
  const patch = read('cordis.patch.yml')
  assert.match(patch, /id: safe-delete/)
  assert.match(patch, /name: '\.\/index\.js'/)
})

test('locale files are valid JSON with display metadata', () => {
  for (const locale of ['locale/en.json', 'locale/zh.json']) {
    const bytes = readFileSync(path.join(root, locale))
    assert.notEqual(bytes[0], 0xef, `${locale} must not have a BOM`)
    const data = JSON.parse(bytes.toString('utf8'))
    assert.ok(data.meta.title.length > 0)
    assert.ok(data.meta.description.length > 0)
  }
})

test('the icon exists and is an SVG', () => {
  const icon = read('icon.svg').trim()
  assert.match(icon, /^<svg[\s>]/)
  assert.ok(statSync(path.join(root, 'icon.svg')).size < 256 * 1024)
})

test('every runtime module named by the manifest exists', () => {
  for (const file of ['index.js', 'lib/guard.js', 'lib/shell.js', 'lib/program.js', 'lib/trash.js', 'lib/paths.js']) {
    assert.ok(statSync(path.join(root, file)).isFile(), file)
  }
})

test('CHANGELOG starts with the package version', () => {
  const manifest = JSON.parse(read('package.json'))
  const changelog = read('CHANGELOG.md').replace(/\r\n/g, '\n')
  assert.match(changelog, new RegExp(`^# Changelog\\n\\n## ${manifest.version.replaceAll('.', '\\.')}`))
})

test('package.json exports all resolve to existing files', () => {
  const manifest = JSON.parse(read('package.json'))
  for (const target of Object.values(manifest.exports ?? {})) {
    assert.equal(typeof target, 'string')
    if (target.includes('*')) {
      const dir = path.join(root, path.dirname(target))
      const suffix = path.basename(target).replace('*', '')
      assert.ok(
        readdirSync(dir).some((name) => name.endsWith(suffix)),
        `export pattern ${target} matched nothing`,
      )
    } else {
      assert.ok(statSync(path.join(root, target)).isFile(), target)
    }
  }
})

test('README files reference the current package version', () => {
  const manifest = JSON.parse(read('package.json'))
  const tag = `v${manifest.version}`
  for (const file of ['README.md', 'README.zh-CN.md']) {
    assert.ok(read(file).includes(tag), `${file} must reference ${tag}`)
  }
})
