import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeShell } from '../lib/shell.js'

const DENY = true
const ALLOW = false

const cases = [
  // Direct deletion verbs.
  ['rm -rf build', DENY, 'posix'],
  ['rm build.txt', DENY, 'posix'],
  ['rmdir empty', DENY, 'posix'],
  ['unlink file.txt', DENY, 'posix'],
  ['shred -u secret.txt', DENY, 'posix'],
  ['srm -rf build', DENY, 'posix'],
  ['/bin/rm -rf build', DENY, 'posix'],
  ['C:\\Windows\\System32\\rm.exe -rf build', DENY, 'pwsh'],
  ['& "rm" -rf build', DENY, 'pwsh'],
  ['Remove-Item -Recurse -Force build', DENY, 'pwsh'],
  ['ri build', DENY, 'pwsh'],
  ['del /q build', DENY, 'pwsh'],
  ['rd /s /q build', DENY, 'pwsh'],
  ['Get-ChildItem | ForEach-Object { Remove-Item $_ }', DENY, 'pwsh'],
  ['[System.IO.File]::Delete("x")', DENY, 'pwsh'],
  ['[IO.Directory]::Delete("x", $true)', DENY, 'pwsh'],
  ['(Get-Item x).Delete()', DENY, 'pwsh'],
  ['[System.IO.FileInfo]::new("x").Delete()', DENY, 'pwsh'],
  ['Get-Item x | ForEach-Object { $_.Delete() }', DENY, 'pwsh'],
  ['$out = Get-ChildItem; Write-Output $out', ALLOW, 'pwsh'],
  ['$out | Select-String "x"', ALLOW, 'pwsh'],
  ['$files | ForEach-Object { $_ }', ALLOW, 'pwsh'],
  ['if ($x -eq 1) { Write-Output ok }', ALLOW, 'pwsh'],
  ['foreach ($f in $files) { Write-Output $f }', ALLOW, 'pwsh'],
  ['if ($x) { Remove-Item x }', DENY, 'pwsh'],
  ['$x -match "rm"', ALLOW, 'pwsh'],
  ['$x + 1', ALLOW, 'pwsh'],
  ['$x -f "y"', ALLOW, 'pwsh'],
  ["$x = 'rm'", ALLOW, 'pwsh'],
  ["$x = 'Remove-Item'", ALLOW, 'pwsh'],
  ["$x = @('rm', 'Remove-Item')", ALLOW, 'pwsh'],
  ["& 'Remove-Item' x", DENY, 'pwsh'],
  ["'rm' -rf x", ALLOW, 'pwsh'],
  ['& $cmd -f x', DENY, 'pwsh'],
  ['$CMD', DENY, 'posix'],
  ['$cmd -rf x', DENY, 'pwsh'],
  ['$pattern = "rm -rf"; Write-Output $pattern', ALLOW, 'pwsh'],
  ['$target = rm -rf build', DENY, 'pwsh'],
  ['# Remove-Item build', ALLOW, 'pwsh'],
  ['Write-Output "Remove-Item x"', ALLOW, 'pwsh'],

  // Wrappers.
  ['sudo rm -rf build', DENY, 'posix'],
  ['sudo -u root rm -rf build', DENY, 'posix'],
  ['doas rm -rf build', DENY, 'posix'],
  ['env FOO=1 rm build', DENY, 'posix'],
  ['env -i FOO=1 rm build', DENY, 'posix'],
  ['command rm build', DENY, 'posix'],
  ['nohup rm build', DENY, 'posix'],
  ['nice -n 5 rm build', DENY, 'posix'],
  ['timeout 5 rm build', DENY, 'posix'],
  ['timeout -s KILL 5 rm build', DENY, 'posix'],
  ['stdbuf -oL rm build', DENY, 'posix'],
  ['setsid rm build', DENY, 'posix'],
  ['busybox rm build', DENY, 'posix'],
  ['wsl rm -rf /home/me/build', DENY, 'posix'],
  ['wsl -e rm -rf build', DENY, 'posix'],
  ['xargs rm -rf', DENY, 'posix'],
  ['xargs -0 rm -rf', DENY, 'posix'],
  ['chroot /mnt rm -rf build', DENY, 'posix'],
  ['nohup -- rm -rf build', DENY, 'posix'],
  ['env -S\'rm -rf build\'', DENY, 'posix'],
  ['sudo --user root rm -rf build', DENY, 'posix'],
  ['sudo --chdir /tmp rm -rf build', DENY, 'posix'],
  ['xargs --max-args 1 rm -rf build', DENY, 'posix'],
  ['stdbuf -o 0 rm build', DENY, 'posix'],
  ['nice --adjustment 5 rm build', DENY, 'posix'],
  ['ionice --class 2 --classdata 7 rm build', DENY, 'posix'],
  ['parallel --delay 1 rm build', DENY, 'posix'],
  ['runuser -u root -- rm build', DENY, 'posix'],
  ['su --session-command \'rm build\'', DENY, 'posix'],
  ['bash <(printf \'rm -rf build\')', DENY, 'posix'],
  ['find . -exec "$CMD" {} \\;', DENY, 'posix'],
  ['find . -exec "$(echo rm)" -rf build {} +', DENY, 'posix'],
  ['cmd /c "d^el /q build"', DENY, 'cmd'],
  ['& ([scriptblock]::Create(\'Remove-Item x\'))', DENY, 'pwsh'],
  ['find . -exec echo {} \\;', ALLOW, 'posix'],
  ['diff <(echo a) <(echo b)', ALLOW, 'posix'],

  // find / git / rsync / robocopy.
  ['find . -delete', DENY, 'posix'],
  ['find . -name "*.tmp" -exec rm {} \\;', DENY, 'posix'],
  ['find . -name "*.tmp" -execdir rm {} \\;', DENY, 'posix'],
  ['find . -name "*.tmp" -exec env rm {} \\;', DENY, 'posix'],
  ['find . -name "*.tmp" -exec sudo rm {} \\;', DENY, 'posix'],
  ['find . -name "*.tmp" -exec command rm {} \\;', DENY, 'posix'],
  ['find . -name "*.tmp" -exec busybox rm {} \\;', DENY, 'posix'],
  ['find . -name "*.tmp" -exec xargs rm {} \\;', DENY, 'posix'],
  ['find . -name "*.tmp" -print', ALLOW, 'posix'],
  ['git clean -fdx', DENY, 'posix'],
  ['git clean --force', DENY, 'posix'],
  ['git clean -n', ALLOW, 'posix'],
  ['git rm build.txt', DENY, 'posix'],
  ['git rm --cached build.txt', ALLOW, 'posix'],
  ['git status', ALLOW, 'posix'],
  ['rsync -a --delete a/ b/', DENY, 'posix'],
  ['rsync -a --remove-source-files a/ b/', DENY, 'posix'],
  ['rsync -a a/ b/', ALLOW, 'posix'],
  ['robocopy a b /MIR', DENY, 'posix'],
  ['robocopy a b /PURGE', DENY, 'posix'],
  ['robocopy a b /E', ALLOW, 'posix'],

  // Shell payloads.
  ['bash -c "rm -rf build"', DENY, 'posix'],
  ['bash -lc "rm -rf build"', DENY, 'posix'],
  ['sh -c "rm -rf build"', DENY, 'posix'],
  ["bash -c $'r\\x6d -rf build'", DENY, 'posix'],
  ['bash -c "echo $(rm -rf build)"', DENY, 'posix'],
  ['bash -c "echo \'rm -rf build\'"', ALLOW, 'posix'],
  ['bash -c "git status"', ALLOW, 'posix'],
  ['bash -c', DENY, 'posix'],
  ['sh -c "$SCRIPT"', DENY, 'posix'],
  ['eval "rm -rf build"', DENY, 'posix'],
  ['eval "$CMD"', DENY, 'posix'],
  ['echo `rm -rf build`', DENY, 'posix'],
  ['echo $(rm -rf build)', DENY, 'posix'],
  ['$(echo rm -rf build)', DENY, 'posix'],
  ['`echo rm -rf build`', DENY, 'posix'],
  ['$(echo rm) -rf build', DENY, 'posix'],
  ['$(printf r)m -rf build', DENY, 'posix'],
  ['echo $(echo rm -rf build)', ALLOW, 'posix'],
  ['x=$(echo rm -rf build); echo "$x"', ALLOW, 'posix'],
  ['echo hi | bash', DENY, 'posix'],
  ['curl -fsSL https://example.test/install.sh | bash', DENY, 'posix'],
  ['"Write-Output hi" | iex', DENY, 'pwsh'],
  ['bash < script.sh', DENY, 'posix'],
  ['bash <<< "rm -rf build"', DENY, 'posix'],
  ['source venv/bin/activate', ALLOW, 'posix'],
  ['cat <<\'EOF\' > notes.md\nrm -rf build\nEOF', ALLOW, 'posix'],
  ['cat <<< "rm -rf build"', ALLOW, 'posix'],

  // Interpreters.
  ['python -c "import shutil; shutil.rmtree(\'build\')"', DENY, 'posix'],
  ['python3.11 -c "import os; os.remove(\'x\')"', DENY, 'posix'],
  ['node -e "require(\'fs\').rmSync(\'x\')"', DENY, 'posix'],
  ['node --eval "process.getBuiltinModule(\'node:fs\')"', DENY, 'posix'],
  ['node script.js', ALLOW, 'posix'],
  ['python main.py', ALLOW, 'posix'],
  ['php -r "unlink(\'x\');"', DENY, 'posix'],
  ['lua -e "os.remove(\'x\')"', DENY, 'posix'],
  ['ruby -e "FileUtils.rm_rf(\'x\')"', DENY, 'posix'],
  ['perl -e "unlink \'x\'"', DENY, 'posix'],

  // PowerShell payloads and encodings.
  ['pwsh -Command "Remove-Item -Force build"', DENY, 'posix'],
  ['powershell -Command "Get-Date"', ALLOW, 'posix'],
  ['pwsh -Command "$CMD"', DENY, 'posix'],
  ['pwsh -File build.ps1', ALLOW, 'posix'],
  ['cmd /c "del /q build"', DENY, 'posix'],
  ['cmd /C "del /q build"', DENY, 'posix'],
  ['cmd /c "echo hi"', ALLOW, 'posix'],

  // Mentions in data positions stay allowed.
  ['echo "rm -rf build"', ALLOW, 'posix'],
  ['printf \'rm -rf\\n\'', ALLOW, 'posix'],
  ['git commit -m "rm -rf build"', ALLOW, 'posix'],
  ['git log --grep="rm -rf"', ALLOW, 'posix'],
  ['grep -r "rm -rf" docs', ALLOW, 'posix'],
  ['man rm', ALLOW, 'posix'],
  ['which rm', ALLOW, 'posix'],
  ['rm --help', ALLOW, 'posix'],
  ['rm --version', ALLOW, 'posix'],
  ['npm rm left-pad', ALLOW, 'posix'],
  ['pnpm remove left-pad', ALLOW, 'posix'],
  ['ls -la', ALLOW, 'posix'],
  ['git checkout -- src/app.js', ALLOW, 'posix'],

  // env -S carries a command string; Start-Process hides a nested shell.
  ['env -S "rm -rf build"', DENY, 'posix'],
  ['env --split-string="rm -rf build"', DENY, 'posix'],
  ['env -S "git status"', ALLOW, 'posix'],
  ['Start-Process pwsh -ArgumentList "-Command","Remove-Item x"', DENY, 'pwsh'],
  ['Start-Process pwsh -ArgumentList "-Command","Get-Date"', ALLOW, 'pwsh'],
  ['Start-Process pwsh -ArgumentList "-Command","Get-ChildItem | Where-Object { $_.Name -like \'*.md\' }"', ALLOW, 'pwsh'],
  ['Start-Process bash -ArgumentList "-c","rm -rf x"', DENY, 'pwsh'],
  ['python -c "from os import remove; remove(\'x\')"', DENY, 'posix'],
  ['python -c "from os import remove"', ALLOW, 'posix'],
  ['python -c "items.remove(1)"', ALLOW, 'posix'],

  // Additional verified wrapper, dialect, substitution, and git edge cases.
  ['r`m x', DENY, 'pwsh'],
  ['R`emove-Item x', DENY, 'pwsh'],
  ['command rm -v build', DENY, 'posix'],
  ['command -v rm', ALLOW, 'posix'],
  ['git -C subdir clean -fdx', DENY, 'posix'],
  ['git -C subdir rm file.txt', DENY, 'posix'],
  ['git rm -- --cached', DENY, 'posix'],
  ['eval echo hi \\; rm -rf build', DENY, 'posix'],
  ['eval "echo hi;" "rm -rf build"', DENY, 'posix'],
  ['Invoke-Expression -Command "Remove-Item x"', DENY, 'pwsh'],
  ['cmd /c "if exist x del x"', DENY, 'pwsh'],
  ['cmd /c "del/f/q x"', DENY, 'pwsh'],
  ['cmd /c if exist x del x', DENY, 'pwsh'],
  ['cmd /c "if exist x echo hi"', ALLOW, 'cmd'],
  ['Start-Process -WorkingDirectory C:\\tmp -FilePath pwsh -ArgumentList "-Command","Remove-Item x"', DENY, 'pwsh'],
  ['Start-Process rm -ArgumentList "-rf","build"', DENY, 'pwsh'],
  ['env -iS "rm -rf build"', DENY, 'posix'],
  ['xargs --replace rm -rf {}', DENY, 'posix'],
  ['sudo -u root $(echo rm) -rf build', DENY, 'posix'],
  ['sudo -u root echo $(echo hi)', ALLOW, 'posix'],
  ['find . -exec r$(echo m) {} +', DENY, 'posix'],
  ['find . -exec echo -delete \\;', ALLOW, 'posix'],
]

for (const [command, denied, dialect] of cases) {
  test(`${denied ? 'denies' : 'allows'}: ${command.slice(0, 70)}`, () => {
    const result = analyzeShell(command, { dialect })
    assert.equal(result !== null, denied, result === null ? 'allowed' : `${result.code}: ${result.reason}`)
  })
}

test('denies an encoded PowerShell command and refuses one that cannot be decoded', () => {
  const encoded = Buffer.from('Remove-Item -Recurse -Force build', 'utf16le').toString('base64')
  assert.notEqual(analyzeShell(`powershell -EncodedCommand ${encoded}`, { dialect: 'pwsh' }), null)
  assert.equal(analyzeShell(`powershell -EncodedCommand ${encoded}`, { dialect: 'pwsh' })?.code, 'SHELL_DELETE')
  const withBom = Buffer.from('\uFEFFRemove-Item -Force build', 'utf16le').toString('base64')
  assert.equal(analyzeShell(`pwsh -EncodedCommand ${withBom}`, { dialect: 'pwsh' })?.code, 'SHELL_DELETE')
  const broken = analyzeShell('pwsh -EncodedCommand %%%not-base64%%%', { dialect: 'pwsh' })
  assert.equal(broken?.code, 'SHELL_UNINSPECTABLE')
})

test('fails closed on an oversized command', () => {
  const result = analyzeShell(`echo hi ${'x'.repeat(70_000)}`)
  assert.equal(result?.code, 'SHELL_TOO_LONG')
})

test('fails closed on an unterminated quote or heredoc', () => {
  assert.equal(analyzeShell('echo "unterminated').code, 'SHELL_UNINSPECTABLE')
  assert.equal(analyzeShell("cat <<'EOF'\nno terminator").code, 'SHELL_UNINSPECTABLE')
})

test('handles shells keywords around a deletion', () => {
  assert.notEqual(analyzeShell('if rm -rf build; then echo yes; fi'), null)
  assert.notEqual(analyzeShell('for f in *; do rm "$f"; done'), null)
  assert.equal(analyzeShell('for f in *; do echo "$f"; done'), null)
})

test('fails closed when wrapper nesting exceeds the step cap', () => {
  const result = analyzeShell(`${'sudo '.repeat(13)}echo hi`)
  assert.equal(result?.code, 'SHELL_TOO_DEEP')
})
