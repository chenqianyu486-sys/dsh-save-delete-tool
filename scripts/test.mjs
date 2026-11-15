import { readdirSync } from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

const testDir = path.join(process.cwd(), 'test')
const files = readdirSync(testDir)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => path.join(testDir, name))

const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' })
if (result.error) throw result.error
process.exit(result.status ?? 1)
