import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeProgram } from '../lib/program.js'

const DENY = true
const ALLOW = false

const cases = [
  ['const fs = await import("node:fs"); fs.rmSync(dir, { recursive: true })', DENY],
  ['await fs.promises.rm(dir, { recursive: true })', DENY],
  ['await fs.rm(dir, { recursive: true })', DENY],
  ['const { rm } = await import("node:fs/promises"); await rm(dir)', DENY],
  ['unlink(path)', DENY],
  ['unlinkSync(path)', DENY],
  ['rmdir(path)', DENY],
  ['rimraf(dir)', DENY],
  ['rimraf.sync(dir)', DENY],
  ['fsExtra.remove(dir)', DENY],
  ['fse.emptyDir(dir)', DENY],
  ['await Deno.remove(path, { recursive: true })', DENY],
  ['execSync("rm -rf build")', DENY],
  ['exec("git clean -fdx")', DENY],
  ['spawn("rm", ["-rf", dir])', DENY],
  ['spawn("git", ["clean", "-fdx"])', DENY],
  ['spawn("git", ["clean", "-n"])', ALLOW],
  ['execFile("python", ["-c", "import shutil; shutil.rmtree(\\"x\\")"])', DENY],
  ['execFile("unlink", ["x"])', DENY],
  ['new Deno.Command("rm", { args: ["-rf", dir] })', DENY],
  ['Bun.spawn(["rm", "-rf", dir])', DENY],
  ['execSync(`rm -rf ${dir}`)', DENY],
  ['await pwsh({ command: "rm -rf build" })', DENY],
  ['await pwsh({ "command": "Remove-Item x" })', DENY],
  ["await pwsh({ 'command': 'Remove-Item x' })", DENY],
  ['await terminal_send({ "text": "rm -rf x" })', DENY],
  ['await pwsh({ description: "cleanup", command: "rm -rf build" })', DENY],
  ['await pwsh({ "description": "rm old build", "command": "git status" })', ALLOW],
  ['await pwsh({ "rm": "note", "command": "git status" })', ALLOW],
  ['await pwsh({ command: "git status" })', ALLOW],
  ['await run_code({ code: "fs.rmSync(dir)" })', DENY],
  ['await run_code({ code: "fs.readFileSync(path)" })', ALLOW],
  ['const wrapped = `${fs.rmSync(dir)}`', DENY],

  ['const text = "fs.rmSync(x)"', ALLOW],
  ['// fs.rmSync(x)', ALLOW],
  ['/* unlink(path) */', ALLOW],
  ['fs.readFileSync(path)', ALLOW],
  ['fs.writeFileSync(path, "x")', ALLOW],
  ['fs.renameSync(a, b)', ALLOW],
  ['execSync("npm test")', ALLOW],
  ['execSync("git status")', ALLOW],
  ['const result = /x/.exec(text)', ALLOW],
  ['const remove = (value) => value; remove(1)', ALLOW],
  ['const repo = getRepo(); repo.rm(1)', ALLOW],
  ['const repo = getRepo(); repo.unlink(1)', ALLOW],
  ['function unlink(x) { return x }', ALLOW],
  ['const unlink = (x) => x; unlink(1)', ALLOW],
  ['function unlink(x) { fs.unlinkSync(x) }', DENY],
  ["require('fs').rmSync('x')", DENY],
  ["const command = 'rm -rf build'", ALLOW],
  ['fs["rmSync"](dir)', ALLOW],
  ['const m = await import("node:fs"); m.rmSync(dir)', DENY],
  ['const f = fs.rmSync; f(dir)', DENY],
  ['const m = require("fs"); m.rm(dir)', DENY],
  ['const { rmSync: f } = fs; f(dir)', DENY],
  ['const m = await import("node:fs"); m.readFileSync(path)', ALLOW],
  ['const fs = require("fs"); const p = fs.promises; p.rm(dir)', DENY],
  ['const { promises: p } = require("fs"); p.rm(dir)', DENY],
  ['const p = fs.promises; p.readFile(path)', ALLOW],
  ['const f = fs.readFileSync; f(path)', ALLOW],
  ['const { exec } = require("child_process"); exec("r" + "m -rf x")', DENY],
  ['await tools.bash({ command: "r" + "m -rf x" })', DENY],
  ['await tools.bash({ command: "git status" })', ALLOW],
  ['Deno.removeSync(path)', DENY],
  ['execFile("python", ["-c", "import os; os.system(\"rm -rf x\")"])', DENY],
  ['execFile("python", ["-c", "print(1)"])', ALLOW],
  ['exec("git", "status")', ALLOW],
  ['require("vm").runInThisContext(source)', DENY],
  // Literal text, argv data and metadata are not commands by themselves.
  ['const re = /[\'"]/', ALLOW],
  ["const re = /it's/", ALLOW],
  ['execFile("git", ["commit", "-m", "rm old build"])', ALLOW],
  ['spawn("rg", ["-n", "rm", "docs"])', ALLOW],
  ['pwsh({ description: "rm old build", command: "npm test" })', ALLOW],
  ['await pwsh({ command: "foreach ($f in @(\'a\')) { Write-Output $f }" })', ALLOW],
  ['await pwsh({ command: "Get-ChildItem | Where-Object { $_.Name -like \'*.md\' }" })', ALLOW],
  ['execFile("python", ["-c", "from os import remove; remove(\'x\')"])', DENY],
  ['execFile("pwsh", ["-Command", "Get-ChildItem | Where-Object { $_.Name -like \'*.md\' }"])', ALLOW],
  ['execFile("pwsh", ["-Command", "Remove-Item x"])', DENY],
  ['execFile("cmd", ["/c", "del x"])', DENY],
  ['spawn("rm", ["--help"])', ALLOW],

  // Static imports, destructuring, concatenation, and argv metacharacters.
  ['import * as m from "node:fs"; m.rmSync(dir)', DENY],
  ['import { rmSync as del } from "node:fs"; del(dir)', DENY],
  ['const { existsSync, rmSync: del } = await import("node:fs"); del(dir)', DENY],
  ['const m = await import("node:fs"); const p = m.promises; p.rm(dir)', DENY],
  ['getRepo().then(r => r.remove(1))', ALLOW],
  ['exec("r" + suffix)', DENY],
  ['await pwsh({ command: "r" + suffix })', DENY],
  ['execFile("git", ["commit", "-m", "fix; rm old"])', ALLOW],
  ['spawn("rg", ["-e", "foo|rm", "docs"])', ALLOW],
  ['execSync("git status", { cwd: "/tmp/a;rm" })', ALLOW],
  ['execFile("cmd", ["/C", "del/q x"])', DENY],
  ['execFile("pwsh", ["-Command", "Get-ChildItem | Remove-Item"])', DENY],
  [`execFile("pwsh", ["-EncodedCommand", "${Buffer.from('Remove-Item x', 'utf16le').toString('base64')}"])`, DENY],
  ['await run_code({ description: "fs.rmSync(x)", code: "return 1" })', ALLOW],
  ['await run_code({ code: "fs." + "rmSync(x)" })', DENY],
  ['const s = "\\u{FFFFFF}"', ALLOW],
]

for (const [code, denied] of cases) {
  test(`${denied ? 'denies' : 'allows'}: ${code.slice(0, 66)}`, () => {
    const result = analyzeProgram(code)
    assert.equal(result !== null, denied, result === null ? 'allowed' : `${result.code}: ${result.reason}`)
  })
}

test('denies runtime code evaluation', () => {
  assert.equal(analyzeProgram('eval("1 + 1")')?.code, 'PROGRAM_UNINSPECTABLE')
  assert.equal(analyzeProgram('new Function("return 1")')?.code, 'PROGRAM_UNINSPECTABLE')
  assert.equal(analyzeProgram('vm.runInThisContext(source)')?.code, 'PROGRAM_UNINSPECTABLE')
  assert.equal(analyzeProgram('process.binding("fs")')?.code, 'PROGRAM_UNINSPECTABLE')
  assert.equal(analyzeProgram('process.getBuiltinModule("node:fs")')?.code, 'PROGRAM_UNINSPECTABLE')
})

test('reads a shell command nested inside an interpreter payload', () => {
  const code = "execSync(\"python -c 'import shutil; shutil.rmtree(\\\"x\\\")'\")"
  assert.notEqual(analyzeProgram(code), null)
})

test('fails closed on an oversized program', () => {
  assert.equal(analyzeProgram(`const x = 1; ${'x'.repeat(70_000)}`)?.code, 'PROGRAM_TOO_LONG')
})

test('fails closed on an unterminated string', () => {
  assert.equal(analyzeProgram('const x = "unterminated')?.code, 'PROGRAM_UNINSPECTABLE')
})
