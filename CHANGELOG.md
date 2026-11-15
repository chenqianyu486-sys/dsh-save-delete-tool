# Changelog

## 2.0.3

P2 follow-up after the 2.0.2 release audit. Tool names, schemas, trash layout
and configuration are unchanged.

### Fixed

- **Cross-volume source-removal failure.** If the copy into the trash succeeds
  but removing the source fails, the complete copy is kept as a pending,
  listable/restorable item and the failure is reported as
  TRASH_SOURCE_REMOVE_FAILED with the item id. The delete_file and restore
  overwrite paths no longer delete the copied payload in that case. The legacy
  migration records the copy as pending instead of leaving an unrecorded item.
- **All-or-nothing tool registration.** delete_file, restore_file and
  list_trash are now registered as one surface; if any registration fails, the
  tools that did register are disposed and no prompt, pre-execute listener or
  guard is installed. This prevents advertising an undo that does not exist.
- **Ask-path coverage.** The pre-execute listener now denies a recognized
  deletion even when another listener returns ask, rather than waiting for an
  approval that tools.guard may not be available to re-check. A stricter
  deny/cancel is preserved; a non-deletion keeps the other listener's ask.
- **Windows restore record separators.** inspectRestorePath normalizes
  backslashes to slashes on Windows before splitting, so a hand-edited record
  such as sub\.git\payload cannot hide a protected segment from the check.

### Tests

- 266 tests (264 pass, 2 skipped on Windows): added cross-volume copy retention,
  all-or-nothing companion registration, ask-path denial, and Windows record
  separator coverage.

### Packaging

- Added author, repository, homepage and bugs metadata.
- Pinned engines.dsh to >=0.2.2-rc.3, the version verified in this tree.
- Added GitHub Actions test matrix (Ubuntu/Windows, Node 20/22/24) and a
  v* tag release workflow that uploads the npm tarball artifact.
- Added RELEASING.md with the remote, real-host smoke and npm publish steps.
- Removed the 41 historical audit trash items from the working tree.

## 2.0.2

Safety fixes after the 2.0.1 release audit. Tool names, schemas, trash layout
and configuration are unchanged.

### Fixed

- **Trash item directory boundary.** `assertTrashRoot` now lstat-checks the
  `items` component as well as `.dsh` and `trash`. An `items` symlink or
  junction (or a non-directory) is refused with
  `TRASH_DIR_OUTSIDE_WORKSPACE` / `TRASH_DIR_NOT_DIRECTORY` before
  `ensureLayout` writes anything, and the deepest checked path is resolved
  again after `mkdirSync`. This closes a workspace-jail escape where a
  redirected `.dsh/trash/items` could receive a moved file outside the
  workspace. `list_trash` and `restore_file` use the same check.
- **Trash .gitignore is never written through a link.** The file is created
  with `wx` only when it does not already exist, so a dangling symlink or a
  hard link cannot redirect the write.
- **PTC bound shell quoted keys.** `argumentKey` now recognizes both bare and
  quoted object keys, so `pwsh({ "command": "Remove-Item x" })` and
  `terminal_send({ "text": "rm -rf x" })` are analyzed instead of skipped.
- **Local deletion-name false positives.** Bare `rm()` / `unlink()` patterns
  no longer match a method receiver such as `repo.rm(1)`; locally defined
  functions and arrows with a deletion verb name are masked. A local function
  that actually calls `fs.unlinkSync` is still refused.
- **require('fs') coverage retained.** `require(...).rmSync(...)`,
  `require(...).promises.rm(...)` and the corresponding unlink/rmdir forms are
  still denied after the method-receiver narrowing.

### Tests

- 261 tests (259 pass, 2 skipped on Windows): added quoted-key, terminal text,
  `repo.rm` / `repo.unlink`, local function/arrow, `fs` inside a local
  function, `require('fs')`, and redirected `items` path coverage.

## 2.0.1

Safety and false-positive fixes after the 2.0.0 release audit. No tool names,
schemas, trash layout or configuration changed.

### Fixed

- **PTC nested shell dialect.** A program that calls `pwsh({ command: ... })`
  is now analyzed as PowerShell, not POSIX, so `foreach`,
  `Where-Object { $_.Name }` and `$var |` pipelines are allowed; a real
  deletion is still refused. A nested uninspectable payload is reported as
  `PROGRAM_UNINSPECTABLE` instead of claiming the command "deletes".
- **Program scanner literals.** Regex literals with quotes (for example
  `/['"]/`) no longer abort the scan as an unterminated string. A shell-out
  analyzes the command and the joined argv, not every string literal; metadata
  such as `description` and `workdir` is ignored, so
  `spawn("rg", ["rm"])`, `execFile("git", ["commit", "-m", "rm old"])`
  and `pwsh({ description: "rm ..." })` are allowed.
- **Sandbox jail root.** `delete_file` / `restore_file` /
  `list_trash` now use the sandbox policy's `workspaceRoot` (falling
  back to the session header cwd), not the mutable working directory. A `cd`
  can no longer move the jail outside the `workspace-write` fence, and
  relative paths are workspace-relative as documented.
- **`list_trash` is a read.** It no longer creates `.dsh/trash` or
  `.gitignore` in a read-only session. An existing 1.x trash is shown
  from its manifest and adopted by the next mutation.
- **`env -S` / `--split-string`.** The payload is analyzed instead of
  being skipped as a flag value.
- **PowerShell `Start-Process`.** A launcher that starts pwsh, cmd or an
  interpreter is followed into its argument list.
- **Python from-import deletions.** `from os import remove; remove(...)` and
  `from shutil import rmtree; rmtree(...)` are refused inside
  `python -c`.
- **Trash path links.** Every existing trash path component is lstat-checked; a
  symlink (including a dangling one) yields `TRASH_DIR_OUTSIDE_WORKSPACE`
  instead of being followed, and a non-directory component yields
  `TRASH_DIR_NOT_DIRECTORY`.
- **Prompt and refusal wording.** The prompt now says the guard refuses
  recognized calls and that scripts/binaries are outside the layer; an
  uninspectable call is described as such instead of "an irreversible deletion".
- **SECURITY #25 and #4** updated to match the symlink-payload race and the
  lstat-based trash path check.

### Tests

- 249 tests (247 pass, 2 skipped on Windows): added coverage for PTC PowerShell,
  regex literals, argv and metadata, sandbox root vs changed cwd, read-only list,
  `env -S`, `Start-Process` and Python from-import.


## 2.0.0

A reset to the MiniMax Code CLI stance: make the delete primitive recoverable,
keep the judgement layer small, and stop pretending a text scanner is the
security boundary. The 1.x scanner had grown to roughly 4,500 lines of source
and 2,300 lines of tests; the replacement is about 3,000 lines of source and
1,400 lines of tests, with 225 tests.

### Changed

- **Package name: `dsh-safe-delete-tool`.** The npm name `dsh-safe-delete`
  already belongs to an unrelated plugin (different tool names, a
  permanent-delete `purge`, Apache-2.0), so this package publishes under its own
  name and an install cannot resolve to that implementation. Runtime names — the
  `safe-delete` row, `delete_file` / `restore_file` / `list_trash`, `.dsh/trash`
  — are unchanged.
- **Trash layout: one directory per deletion.** `items/<id>/meta.json` plus
  `items/<id>/payload` replaces the global `manifest.json`, its `.bak`, the
  append-only audit log, the cross-process lock and the in-process write queue.
  Independent item directories cannot overwrite each other, need no lock, and
  are self-describing after a crash.
- **Ids are monotonic.** `YYYYMMDDTHHMMSSmmm-<hex>` (millisecond timestamp plus
  random suffix) keeps rapid deletes in a stable newest-first order. 1.x ids
  are still accepted.
- **The guard classifies by schema shape.** A string `command` parameter means
  shell; a string `code` parameter means program. This covers `standard`
  (`pwsh`), `ptc` (`run_code`), `minimal` (persistent `pwsh`) and `cordis`
  (shell plus read-only inspection tools) without per-preset name lists.
- **The shell guard is text-only.** It no longer reads script files, follows
  `git` history rules, or tries to decode arbitrary payloads. It handles direct
  verbs, wrappers, `bash -c` / `pwsh -Command` / interpreter payloads, command
  substitution, heredocs, `-EncodedCommand`, pipes into a shell and runtime
  command names, and fails closed when it cannot inspect.
- **The program guard is lexical and small.** It blanks comments and strings,
  keeps template expressions visible, rejects filesystem deletion calls,
  runtime evaluation, and `child_process` / `execa` / `Deno.Command` literals
  that run a deleting shell command.
- **Zero configuration.** The trash path, protected segments and guard policy
  are fixed. The 10-field config surface, its optional `schemastery` loader and
  the config tests are gone.
- **`list_trash` returns 10 items by default** (was 20) and no longer has a
  `verbose` mode; `trash_id` still fetches one item.
- **Refusals name the plugin version** (`[dsh-safe-delete-tool v2.0.0] …`) so a
  module left over from before a restart is visible instead of silently
  guarding with old rules.

### Added

- **Automatic 1.x migration**: `manifest.json` plus flat
  `items/<id>__name` archives are adopted into item directories on first use.
- **Per-item pending state**: an interrupted move leaves a record that
  `list_trash` shows and `restore_file` accepts.
- **Trash-root check**: a `.dsh` or trash directory that resolves outside the
  workspace is refused (`TRASH_DIR_OUTSIDE_WORKSPACE`) before the plugin writes
  to it.
- **Native patch and terminal coverage**: `apply_patch` is refused when its
  input contains a `*** Delete File:` hunk (`PATCH_DELETE`), and an optional
  `terminal_send` tool is recognized by its `text` + `sessionId`/`submit`
  shape and scanned as typed shell input.
- **PTC binding coverage**: a program that calls a bound shell tool
  (`pwsh({ command: "rm -rf build" })`) or nests `run_code` is refused, not
  just a program that imports `fs` or `child_process` directly.
- **Four-preset tests** through a fake Cordis context: standard, PTC, minimal
  and cordis, plus the shell/program classification and the pre-execute/guard
  pipeline.
- **A sandbox-mode gate.** `delete_file` and `restore_file` move files with
  `node:fs`, so the Harness filesystem fence never sees them; both now resolve
  the same per-call `ctx.sandboxPolicy` and refuse a `read-only` session
  (`SANDBOX_READ_ONLY`), failing closed when the policy service exposes no
  `resolve()`, throws, or returns an unknown mode
  (`SANDBOX_POLICY_UNAVAILABLE`). `dry_run` and `list_trash` stay available,
  and a host without the policy service is not gated.
- **Contract pins** (`test/contract.test.mjs`): the definition shape the Host
  reads, `VERSION` agreement with `package.json`, and the rule that neither the
  guard nor the prompt is installed when `delete_file` failed to register.

### Removed

- `lib/shell-guard.js` (1,683 lines), `lib/program-guard.js`, `lib/script-scan.js`,
  `lib/config.js`, `lib/schema.js`.
- Cross-process locking, retention pruning, the audit log, `.gitignore`
  editing, script-file scanning, git destructive-command rules beyond
  `git clean -f` / `git rm`, and the `shellPolicy` idea.
- The `@deepseek-ai/schemastery` optional peer.

### Fixed

- Restore now refuses a malformed id (`INVALID_TRASH_ID`) instead of treating
  it as a missing item.
- **Refusal codes reach the model and the log.** `SafeDeleteError` messages are
  prefixed with their stable code (`[PATH_OUTSIDE_WORKSPACE] …`); the
  structured `info` identity is not persisted for a plain `Error`, so the text
  is the contract.
- **Restore no longer replaces a file that appeared mid-restore.** A file
  payload is hard-linked into place first, so `link` fails with `EEXIST`
  instead of a POSIX `rename` overwriting it; a rename fallback re-checks the
  destination (so a permission failure cannot become a silent replace), a
  dangling symlink is seen through `lstat`, and a cross-volume fallback copies
  to a temporary sibling before renaming so a failed copy cannot block every
  later restore.
- **A call with no session working directory is refused**
  (`WORKSPACE_UNAVAILABLE`) instead of jailing to the Host process directory,
  which used to put the deletion jail on the installation folder.
- **The deletion guard is not installed when `delete_file` cannot register.**
  Refusing `rm` while the recoverable replacement is missing left the model
  with no way to delete at all.
- `git rm --cached` stays allowed; `git clean -n` stays allowed.
- An empty directory no longer requires `recursive: true`.

## 1.2.0

PTC mode (`run_code`) is now covered. A program deletes with
`await import('node:fs')` and `fs.rmSync(...)` instead of a shell command, so the
shell guard never saw it; the same pre-execute hook and guard now scan the program
text too.

### Added

- **A program scanner (`lib/program-guard.js`) behind `blockProgramDeletions`**,
  applied to `programToolNames` (`["run_code"]` by default). It denies:
  - filesystem deletion through a namespace, a destructured binding, an inline
    import or a `createRequire`: `fs.rmSync`, `fs.promises.rm`, `unlink`,
    `unlinkSync`, `rmdir`, `rmdirSync`, `remove` (fs-extra), `emptyDir`,
    `rimraf`, `rimraf.sync`, and aliases of all of them;
  - `child_process` / `execa` / Bun / Deno / Python shell-outs whose string
    arguments run a deletion, scanned with the existing shell rules (including
    script-file inspection and the git rules);
  - `Deno.remove`, `shutil.rmtree`, `os.remove`, `os.unlink`, `os.rmdir`.
- **Uninspectable programs fail closed**: `eval`, `new Function`, `vm.runIn*`,
  `process.binding`, `process.getBuiltinModule`, and a program longer than
  `maxCommandChars` are refused instead of guessed at.
- The refusal now names the channel: a program refusal says "in the `run_code`
  program" and a shell refusal says "in `pwsh`", instead of always saying shell.
- A tool that takes a `code`/`source` argument but is missing from
  `programToolNames` is reported once, like an unlisted shell tool.
- `blockProgramDeletions` and `programToolNames` in the config schema, the bundle
  patch and both READMEs; `SECURITY.md` gains guarantees 19–20 and the matching
  non-guarantees.

### Tests

- 284 tests (was 267): `test/program-guard.test.mjs` (allow/deny corpus for
  namespaces, destructuring, inline imports, `createRequire`, shell-outs,
  templates, run-time code, lexing and binding discovery) plus PTC integration
  and config cases in `test/smoke.test.mjs` and `test/config.test.mjs`.


## 1.1.2

The 1.1.1 manifest came out of a Windows-PowerShell edit as UTF-8 **with a BOM**.
DSH parses `package.json` as strict JSON without stripping the BOM, so the bundle
was reported as unavailable and the plugin stopped mounting entirely: no
`delete_file` / `restore_file` / `list_trash`, no `<safe_delete>` prompt section,
no shell guard. Everything below is about making that class of failure visible
and impossible to ship.

### Fixed

- **`package.json` is plain UTF-8 again.** First byte is `{`, not `EF BB BF`, so the
  Loader can parse the manifest and insert the `safe-delete` row again.
- **The schema builder is resolved when the plugin is installed as a link.** A bare
  `import('@deepseek-ai/schemastery')` from a linked checkout climbs the checkout's
  parents and fails, which left `Config` undefined: the Plugin Manager showed no
  settings and every boot printed "schemastery is unavailable". The lookup now also
  tries the Host directories (`DSH_PROFILE_DIR`, then `DSH_INSTALL_DIR`), and
  still degrades to defaults when neither has the peer.

### Added

- `test/compat.test.mjs` pins the bundle contract the Host actually enforces: no
  BOM and `JSON.parse` on `package.json`, a patch layer that inserts an existing
  module, `files`/`exports` targets that exist, BOM-free resource JSON, a non-empty
  `engines.dsh`, and `package.json`/`CHANGELOG.md` version agreement.
- `test/schema.test.mjs` covers anchor selection, the link-install fallback, an
  unresolvable anchor, an unusable export shape, and the no-schema path.
- READMEs document the "package unavailable / `Unexpected token '﻿'`" symptom and
  the one-byte check that diagnoses it.

## 1.1.1

Follow-up to the v2 token/safety audit: one fail-open in the shell guard, five
patterns that could still be evaded, and the cross-process lock semantics.

### Fixed

- **A shell argument larger than `maxCommandChars` is refused instead of scanned
  halfway.** The scanner's own "too long to inspect" refusal was unreachable
  because the argument was clipped to the budget before analysis: 64 KB of
  padding followed by a deletion command passed, and a large first argument left
  a later one unscanned. A payload that does not fit the budget is now reported
  as uninspectable.
- `git checkout <path>` / `git checkout docs/` discard uncommitted work exactly
  like `git checkout -- <path>` but were not recognised. A path-shaped operand is
  now refused; `main`, `origin/main`, `feature/x`, `v1.2.3` and `-b feat` stay
  allowed.
- `export RM=rm; $RM -rf build` (and the `declare`/`local`/`env`/`set --` forms)
  names the deletion command outside command position. A quoted operand is still
  data, so `git commit -m "X=rm"` stays allowed.
- ANSI-C quoting is decoded before scanning, so `bash -c $'r\x6d -rf build'` is
  caught while an ordinary `$'a\nb'` keeps working.
- `eval` / `Invoke-Expression` of a decoded payload (`base64 -d`, `printf` with
  `\xNN`, `[Text.Encoding]`, `Convert::FromBase64String`) fails closed, as does a
  `set --` parameter list that names a deletion command.
- Restore no longer says "nothing was changed" when `overwrite: true` had already
  archived the occupant; the message names the new `trash_id`.
- A manifest write is read back and verified before the backup is refreshed, and a
  `reason` read from a hand-edited manifest is capped like one that was written.
- A workspace fallback to the Host process directory is announced once instead
  of being silent.

### Changed

- **Cross-process lock semantics.** The lock records `pid`, `host` and an
  ownership token; the holder refreshes its mtime every 5 s (so a long synchronous
  move is not mistaken for a crash), and a release only deletes a lock whose token
  still matches. Staleness is decided by the owner's pid on the same host and by
  the heartbeat elsewhere. The lock is taken after validation and layout
  creation, so the first-ever delete into a fresh trash is serialized and a
  refused delete creates nothing.
- Tool results flatten control characters in paths, reasons and trash ids, so a
  file name containing a newline cannot forge extra result lines.
- `delete_file` / `restore_file` descriptions no longer repeat what their
  parameters already say (fixed cost 2 216 → 2 087 characters per request).

## 1.1.0

Security and context-cost release, driven by a token-efficiency and
safety-boundary audit.

### Fixed

- **The shell guard now scans every string argument of a shell tool**, not only
  `command`. The host `wsl` tool documents a `stdin` parameter, so
  `wsl(command: "bash", stdin: "rm -rf x")` used to run the script unguarded;
  that path is now denied like any other payload. Metadata arguments
  (`description`, `workdir`, `distro`, `env`, labels) are skipped.
- Versioned interpreter names are normalized, so `python3.11 -c "…rmtree…"` is no
  longer invisible while `python3 -c` was caught.
- `@del` / `@erase` (cmd echo suppression) and `for %f in (*) do @del %f` are
  recognised.
- `bash <<< 'rm -rf x'` (here-string) and `bash <(echo …)` (process substitution)
  are scanned as code when a shell consumes them.
- `RM=rm; $RM -rf build` (assignment indirection) and a quoted command line handed
  to a wrapper (`parallel 'rm -rf {}' ::: x`) are denied.
- `base64 -d … | bash`, `zcat … | bash` and similar decode/compression pipelines
  now fail closed like an undecodable `-EncodedCommand`.
- **A script file the command runs is read and scanned**: `bash run.sh`,
  `pwsh -File x.ps1`, `python main.py`, `bash < run.sh`. Bounded to 64 KB; a
  binary, oversized, unreadable or explicitly-named-but-missing file is refused.
- Destructive git commands are denied (`blockGitDestructive`): `reset --hard`,
  `checkout -- <path>` / `checkout .`, `restore <path>`, `stash drop|clear`,
  `branch -D`, `worktree remove --force`, and `git rm` without `--cached`. The
  safe siblings (`git restore --staged`, `git checkout -b`, `git branch -d`,
  `git rm --cached`) stay allowed.
- A cross-volume move only falls back on `EXDEV`, and the copy is **verified**
  against the source (entry count and bytes) before the original is removed. A
  failed copy is cleaned up instead of being left as an unindexed archive.
- A manifest write failure after a successful move no longer reports the delete as
  failed; it returns `ok` with `warning: manifest_not_committed`.
- The target is re-proved immediately before the move (`PATH_CHANGED`), and the
  tree is counted on the archive rather than before the move.
- Cross-process serialization with a lock file (`crossProcessLock`), with stale
  lock takeover.
- `.gitignore` is never written through a symbolic link.
- A tool that takes a `command` argument but is missing from `shellToolNames` is
  reported once instead of being silently unguarded.

### Changed

- **Retention pruning is opt-in** (`retention.enabled` now defaults to `false`):
  the only permanent-removal path no longer runs after an unrelated delete.
- `list_trash` gains `trash_id` (single-item lookup), `offset` (paging) and
  `verbose` (entry counts and sizes). The default page is now 20, timestamps are
  rendered to the minute, and sizes are omitted unless `verbose` is set.
- The refusal message, the tool descriptions and the system-prompt section were
  rewritten under the harness rule "say each fact once". Fixed model-facing cost
  drops from 3 589 to 2 065 characters per request (−42 %), and a default
  `list_trash` page from ~8.2 KB to ~2.4 KB.
- Path refusals no longer advise changing plugin configuration the model cannot
  change.

### Tests

- 240 tests (was 192), including the audit's bypass corpus: versioned
  interpreters, `@`-prefixed cmd deletes, here-strings, process substitution,
  encoded pipelines, assignments, quoted wrapper command lines, destructive git,
  script-file inspection, argument-channel scanning, retention opt-in, paging and
  the stale-lock takeover.

## 1.0.0

Initial release.

- `delete_file`, `restore_file`, `list_trash` Host tools.
- Workspace jail: `realpath` containment, protected path segments, trash
  overlap refusal, filesystem-root workspace refusal.
- Explicit recursive gate for non-empty directories and `dry_run` previews.
- Journaled trash under `.dsh/trash` with `manifest.json`,
  `manifest.json.bak`, `items/`, and `audit.jsonl`.
- Crash-safe `pending` record reconciliation; one promise queue per workspace.
- Restore with `overwrite` archiving the displaced file instead of unlinking it.
- Retention (`maxItems` / `maxAgeDays`) with disclosure and audit entries.
- Automatic `.gitignore` entry inside git repositories.
- Pre-execute denial plus a synchronous guard for irreversible shell deletion:
  POSIX, PowerShell, cmd, wrappers, `find -exec`, `git clean -f`,
  `rsync --delete`, `robocopy /MIR`, inline interpreters, command substitution,
  heredocs, pipelines-to-shell, and encoded PowerShell.
- Optional system-prompt guidance preferring `delete_file`.
- Config schema with tolerant fallback when `@deepseek-ai/schemastery` is absent.
- 180+ unit/integration tests.
