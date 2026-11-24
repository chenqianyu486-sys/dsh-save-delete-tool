import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { VERSION } from '../index.js'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function collectJsFiles(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      collectJsFiles(full, out)
    } else if (entry.name.endsWith('.js') || entry.name.endsWith('.mjs')) {
      out.push(full)
    }
  }
  return out
}

function runStep(label, args) {
  console.log(`==> ${label}`)
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit' })
  if (result.error) throw result.error
  if ((result.status ?? 1) !== 0) {
    process.exit(result.status ?? 1)
  }
}

// 1. Syntax check across all source, script, and test files
const jsFiles = [
  ...readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.mjs')))
    .map((entry) => path.join(root, entry.name)),
  ...collectJsFiles(path.join(root, 'lib')),
  ...collectJsFiles(path.join(root, 'scripts')),
  ...collectJsFiles(path.join(root, 'test')),
].sort()

console.log(`==> Syntax check (${jsFiles.length} files)`)
for (const file of jsFiles) {
  const check = spawnSync(process.execPath, ['--check', file], { cwd: root, stdio: 'inherit' })
  if (check.error) throw check.error
  if ((check.status ?? 1) !== 0) process.exit(check.status ?? 1)
}

// 2. Package & manifest integrity check
console.log('==> Package integrity check')
const pkgBytes = readFileSync(path.join(root, 'package.json'))
assert.equal(pkgBytes[0], 0x7b, 'package.json must not start with a UTF-8 BOM')
const pkg = JSON.parse(pkgBytes.toString('utf8'))
assert.equal(pkg.version, VERSION, `package.json (${pkg.version}) must match index.js VERSION (${VERSION})`)
for (const entry of pkg.files ?? []) {
  if (entry.includes('*')) {
    const dir = path.join(root, path.dirname(entry))
    const suffix = path.basename(entry).replace('*', '')
    assert.ok(
      readdirSync(dir).some((name) => name.endsWith(suffix)),
      `files pattern ${entry} matched nothing`,
    )
  } else {
    assert.ok(statSync(path.join(root, entry)), `missing files entry: ${entry}`)
  }
}
for (const target of Object.values(pkg.exports ?? {})) {
  if (typeof target !== 'string') continue
  if (target.includes('*')) {
    const dir = path.join(root, path.dirname(target))
    const suffix = path.basename(target).replace('*', '')
    assert.ok(
      readdirSync(dir).some((name) => name.endsWith(suffix)),
      `exports target ${target} matched nothing`,
    )
  } else {
    assert.ok(statSync(path.join(root, target)).isFile(), `missing exports target: ${target}`)
  }
}
for (const locale of ['locale/en.json', 'locale/zh.json']) {
  const bytes = readFileSync(path.join(root, locale))
  assert.notEqual(bytes[0], 0xef, `${locale} must not have a BOM`)
  JSON.parse(bytes.toString('utf8'))
}
const changelog = readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8').replace(/\r\n/g, '\n')
assert.match(changelog, new RegExp(`^# Changelog\\n\\n## ${pkg.version.replaceAll('.', '\\.')}`))

// 3. Full test suite
runStep('Test suite (scripts/test.mjs)', [path.join(root, 'scripts', 'test.mjs')])

// 4. Bundle smoke test
runStep('Bundle smoke (scripts/smoke.mjs)', [path.join(root, 'scripts', 'smoke.mjs')])

console.log(`verify ok (dsh-safe-delete-tool v${VERSION})`)
