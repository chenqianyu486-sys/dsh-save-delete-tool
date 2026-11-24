# dsh-safe-delete-tool

Recoverable file deletion for **DeepSeek Harness (DSH)**.

The plugin does not try to enumerate every dangerous shell spelling. It changes
the delete primitive: deletion goes through `delete_file`, the target moves into
a workspace trash and gets a `trash_id`; `restore_file` undoes it and
`list_trash` shows what is recoverable. The guard has one job — before a tool
call executes, decide whether it is an irreversible delete and point the model
at `delete_file`.

This takes MiniMax Code CLI's goal, not its mechanism. MiniMax rewrites `rm`
at the execution layer: a permission-layer argv rewrite plus an `rm` shim at
the front of `PATH`, so scripts and `xargs` land in the host trash, and a
missing shim refuses to start bash. DSH exposes no such hook —
`tools/pre-execute` deliberately cannot rewrite `exec.arguments`, and a plugin
cannot inject a `PATH`. So the recoverable primitive here is a structured tool,
and the irreversible spellings are left to a text-only judgement layer with no
filesystem access.

## What it registers

- three Host tools: `delete_file`, `restore_file`, `list_trash`;
- one `tools/pre-execute` guided refusal;
- one synchronous `tools.guard` backstop (it still applies after approval; the
  three tools, the prompt, pre-execute and guard are installed only when all
  three tools register successfully);
- one system-prompt paragraph.

No frontend, no configuration, no background pruning, no retention window.

## Install

This repository is a complete DSH bundle (`package.json` declares
`dsh.bundle.patch`):

```text
plugin_manager
  action: install_bundle
  target: <absolute path to this directory>
```

Or in the desktop app: **Plugins → Install → From folder**. The bundle inserts
one process-wide row (`safe-delete`), so every agent preset gets the tools and
the guard. Do not add a second copy to a preset: tool names are global.

Requires DSH `>= 0.2.2-rc.3` (verified on `0.2.2-rc.3`) and Node `>= 20`. No peer dependencies and no
build step.

## Tools

### `delete_file`

| Parameter | Default | Meaning |
|---|---|---|
| `path` | required | Workspace-relative, or absolute inside the workspace. |
| `recursive` | `false` | Required for a non-empty directory; an empty directory needs no flag. |
| `reason` | — | Stored with the trash item and shown by `list_trash`. |
| `dry_run` | `false` | Report type, entry count and whether `recursive` is needed; move nothing. |

A successful call returns a `trash_id` plus the undo command. Refusals use
stable codes such as `RECURSIVE_FLAG_REQUIRED`, `PATH_OUTSIDE_WORKSPACE`,
`PATH_PROTECTED`, `PATH_ALIAS_UNSUPPORTED`, `REFUSE_WORKSPACE_ROOT`, `PATH_IN_TRASH`,
`WORKSPACE_IS_FILESYSTEM_ROOT`, `SANDBOX_READ_ONLY`,
`SANDBOX_POLICY_UNAVAILABLE` and `TRASH_SOURCE_REMOVE_FAILED`. A call made with no session working directory is
refused (`WORKSPACE_UNAVAILABLE`) instead of guessing the Host process
directory.

Never deletable: the workspace root, any path with a `.git`, `.dsh` or
`.env` segment, the trash itself, and a workspace that is a filesystem root.
Windows alternate data streams (`name:stream`), trailing dots or spaces
(`.git.`, `.env `), and 8.3 short names (`GIT~1`) are refused as
`PATH_ALIAS_UNSUPPORTED` rather than guessed at (while non-8.3 filenames
containing `~`, such as `project~2026.txt`, stay allowed).

### `restore_file`

| Parameter | Default | Meaning |
|---|---|---|
| `trash_id` | required | Returned by `delete_file` or listed by `list_trash`. |
| `overwrite` | `false` | Move the current occupant into the trash instead of refusing. |

Restore re-validates the stored path, recreates missing parents inside the
workspace, and rejects a tampered record. It also verifies that `items/<id>` is a
real directory and `meta.json` is a regular file, so a junction/symlink cannot
redirect restore outside the workspace. Redirected or malformed items fail with
`TRASH_ITEM_OUTSIDE_WORKSPACE` / `TRASH_ITEM_INVALID` / `TRASH_ITEM_UNREADABLE`;
a missing item remains `TRASH_ITEM_NOT_FOUND`. It never replaces an existing
file silently: a file payload is hard-linked into place, so a path taken while
the restore runs fails with `DESTINATION_EXISTS` and the item stays in the
trash. The original file mode is preserved (including the Windows read-only
attribute). With `overwrite: true` the displaced occupant gets its own new
`trash_id`, and both sides stay recoverable.

### `list_trash`

| Parameter | Default | Meaning |
|---|---|---|
| `query` | — | Case-insensitive filter over id, original path and reason. |
| `trash_id` | — | Show one known item instead of a page. |
| `limit` | `10` | Items to return (1–100). |
| `offset` | `0` | Items to skip. |

The default page is deliberately small: listing 20 items costs more than all
three tool definitions combined. The result carries a `Next page` hint.

### Sandbox mode

`delete_file` and `restore_file` move files with `node:fs`, outside DSH's
filesystem fence, so they read the session's own sandbox policy and refuse a
`read-only` session with `SANDBOX_READ_ONLY`. A `workspace-write` session keeps
the session workspace (the policy's `workspaceRoot`) as the jail; the mutable
shell cwd is not the boundary, so a `cd` cannot move it outside the fence.
`danger-full-access` behaves as before. A policy service that exists but exposes
no `resolve()`, throws, or resolves to a mode this plugin does not know fails
closed (`SANDBOX_POLICY_UNAVAILABLE`), while a host without the policy service is
not gated. A `dry_run` preview and `list_trash` never mutate and stay available;
`list_trash` does not create or migrate the trash; an existing 1.x trash is
shown from its manifest and adopted by the next mutation.

Refusals and tool failures carry their stable code in the message
(`[SANDBOX_READ_ONLY] …`), so a failure can be matched in a log without the
in-process error object.

## The trash

```
<workspace>/.dsh/trash/
  .gitignore              # `*`, so the trash never enters git
  items/
    <id>/
      meta.json           # original path, kind, reason, session, time, status
      payload             # the moved file or directory
```

**Each item is its own journal.** There is no shared manifest, so two parallel
deletes (or two DSH processes) cannot overwrite each other's records. A delete
writes a `pending` record, moves the payload, then rewrites `trashed`; a crash
in between leaves a `pending` record with a payload, which `list_trash` still
shows and `restore_file` still accepts. Restore validates `items/<id>` and
`meta.json` before reading, so a junction/symlink cannot redirect an item.

Ids look like `20261114T094442123-abcd1234`: millisecond timestamp plus random
suffix, monotonic within one process, so rapid deletes keep a stable newest-first
order.

Cross-volume moves (`EXDEV`) fall back to copy-then-remove; a failed copy only
cleans up the partial copy and leaves the source untouched. If the copy succeeds
but the source cannot be fully removed, the complete copy is kept as a pending
item and the call reports `TRASH_SOURCE_REMOVE_FAILED` with its `trash_id`. A 1.x trash
(`manifest.json` plus flat `items/<id>__name` archives) is shown on first
listing and adopted by the next mutation. Adoption writes a pending record
before the move, removes an empty item directory on failure, and repairs a
payload that landed before its meta write, so an upgrade does not strand
recoverable files.

`realpath` plus per-component `lstat` rejects path-level symlinks and junctions,
but cannot prove that a directory is not a Linux bind mount or an equivalent
physical mount; those mount points and check/use races remain residual risks
documented in SECURITY #26.

## The guard

A refusal names the plugin version (`[dsh-safe-delete-tool v2.0.6] …`), so a
stale module keeps being visible after an upgrade instead of silently guarding
with old rules.

The guard classifies tools by **schema shape**, not by name:

- a string `command` (or `cmd` / `commandLine`) parameter → shell tool;
- a string `code` parameter → program tool (PTC's `run_code`).

That is what makes it work unchanged across presets:

| Agent preset | Relevant tools | Coverage |
|---|---|---|
| `standard` | `pwsh` / `bash` + fs tools | shell guard |
| `ptc` | the shell + `run_code` | shell guard + program guard |
| `minimal` | persistent `pwsh` | shell guard; the tools remain global |
| `cordis` | `pwsh` + `cordis_inspect_*` | shell guard; the inspection tools have no `command`/`code` and are skipped |

Every string argument of a shell tool is scanned (metadata such as
`description` and `workdir` is skipped), so `wsl(command: "bash", stdin: "rm -rf x")`
is seen too.

Refused deletions include:

- POSIX: `rm`, `rmdir`, `unlink`, `shred`, `srm`, through wrappers such as
  `sudo`, `doas`, `env` (including `env -S`), `command`, `exec`, `nohup`, `nice`, `timeout`,
  `stdbuf`, `setsid`, `busybox`, `wsl`, `chroot`, `xargs`, `parallel`, `watch`;
  long and separated option values, `nohup --`, `runuser --`, `su --session-command`,
  and process substitution that can feed a shell are covered;
- PowerShell: `Remove-Item` and aliases (`rm`, `del`, `erase`, `rd`, `rmdir`,
  `ri`), `[System.IO.File]::Delete` / `[IO.Directory]::Delete`, instance methods
  such as `(Get-Item x).Delete()` / `FileInfo.Delete()`, including pipelines,
  `ForEach-Object { ... }`, `& 'rm'`, `Start-Process` launching a shell, and
  `-EncodedCommand`;
- cmd: `del`, `erase`, `rd`, `rmdir`, `cmd /c` payloads, and caret-escaped names
  such as `d^el`;
- native patch deletion: `apply_patch` with a `*** Delete File:` hunk;
- terminal input: `terminal_send` typed shell text, when the optional
  terminal bundle is installed;
- whole-tree deletion: `find -delete`, `find -exec rm` and wrapper forms such as
  `find -exec env|sudo|command|busybox|xargs ...`; a dynamic `-exec` command
  (`$CMD`, `$(...)`) fails closed; `rsync --delete`, `robocopy /MIR|/PURGE`,
  `git clean -f`, `git rm` (except `--cached`);
- readable inline payloads: `bash -c`, `sh -c`, `pwsh -Command`, `cmd /c`,
  `eval`, command-position substitutions and backticks, `python -c` (including
  `from os import remove; remove(...)`), `node -e`, `perl -e`, `ruby -e`,
  `php -r`, `lua -e`. Payloads are analyzed recursively; more than 3 levels
  or 64 KB is refused;
- a PTC program that calls a bound shell tool with a recognized deleting command
  (`pwsh({ command: "rm -rf build" })`), launches a shell through
  `Start-Process`, or nests `run_code`. Command arguments are read by key;
  metadata and argv data are not commands. Module aliases (`import`,
  `require`, `createRequire`, `fs.promises`), method aliases and literal
  command concatenation fail closed.

**Fail closed**: an undecodable PowerShell `-EncodedCommand`, an unterminated
quote or heredoc, a shell that reads its program from a pipe or redirection
(`curl … | bash`, `bash < run.sh`), a process substitution that feeds a shell
(`bash <(…)`), a command-position `$(...)` / backtick substitution, a dynamic
`find -exec` command, a PowerShell `scriptblock::Create` payload, and a command
name built at runtime (`$CMD`, `%COMSPEC%`) are all refused.

**Allowed**: data mentions such as `echo "rm -rf"`,
`git commit -m "rm -rf"`, `grep -r "rm" docs`, `man rm`, `rm --help`,
`git clean -n`, `git rm --cached x`, `npm rm left-pad`, a heredoc written to a
file, and `source venv/bin/activate`.

### What this layer does not do

It is **not a security boundary**. It reads the command text, not script files:

- deletions inside `bash deploy.sh`, `pwsh -File build.ps1` or
  `python main.py` are out of scope;
- runtime-built strings (`$cmd = 'Remove-Item'; & $cmd x`), downloaded
  scripts, computed properties (`fs['rmSync']`) and binaries are out of
  scope;
- disk wipes (`mkfs`, `dd`) and `git reset --hard` are data loss but not file
  deletion, so they are out of scope too;
- typed terminal input is checked per call; a command split across several
  `terminal_send` / `wsl-term` calls is not reconstructed.

Use DSH's sandbox and approval policy for a hard boundary. This plugin makes
ordinary deletion recoverable and obvious irreversible deletion visible. The
complete list is in [SECURITY.md](SECURITY.md).

## Why no configuration

The delete primitive's semantics are fixed: workspace-local targets go to
`.dsh/trash`, a non-empty directory needs an explicit `recursive`, and the
protected segments and the trash cannot be deleted. Turning that into settings
would only add states to test, not make deletion safer.

## Development

```bash
npm run verify
```

`npm run verify` checks syntax across every source/script/test file, validates
`package.json` and `exports` integrity, runs `npm test` (373 tests), and runs
`npm run smoke` (all four presets plus a disposable-workspace smoke suite).

The 373 tests cover the jail (relative/absolute/`..`/symlinks/protected/trash,
Windows ADS, trailing dot/space, and 8.3 aliases, non-8.3 tilde names,
`\\?\` prefixes, `assertSafeExistingParents`, including a redirected `items`
directory and a redirected item directory), the trash (delete, dry-run,
recursive flag, restore of a file and of a directory, overwrite, overwrite
failure recovery messages, paging, filtering, 1.x migration including failure
retry/crash repair/tampered paths, parallel deletes, mode preservation,
dangling symlinks, wrapped OS error codes), the sandbox gate (read-only refusal
for delete and restore, dry-run still available, an unresolvable policy failing
closed), the shell policy (direct commands, wrappers with long/separated option
values, wrapper depth cap, inline payloads, command-position substitutions
inside wrappers/`find -exec`, process substitution, dynamic `find -exec`,
`git` global flags, cmd `if`/switches/caret escapes, PowerShell
backtick escapes/`Delete`/scriptblocks/`Start-Process`, encodings, heredocs,
allowed data mentions), the program policy (`fs.rm`, `unlink`, `rimraf`,
`Deno.remove`, static/dynamic imports, destructuring, module/method aliases,
command concatenation, argv metacharacters, `child_process`, `eval`), and the
plugin assembly, schema-conforming outputs, plus four-preset classification
through a fake Cordis context. On Windows, symlink tests skip when creating a
symlink needs Developer Mode or elevation (or sandbox permission).

Source layout:

```
index.js                 entry: tools, prompt, pre-execute, guard
lib/paths.js             workspace jail, restore-path validation
lib/trash.js             item-directory trash: delete, restore, list, 1.x migration
lib/shell.js             shell deletion policy (quotes, wrappers, inline payloads)
lib/program.js           PTC program deletion policy (including shell-outs)
lib/guard.js             schema-shape classification and dispatch
lib/tools/*.js           delete_file / restore_file / list_trash
```

Reload the profile or restart DSH after changing the plugin source: a loaded
ESM module does not refresh in-process. Until the restart the old build keeps
guarding, and an older text policy can refuse commands the current source
allows — the version tag in the refusal is how that shows up.

## Uninstall

Disable the `safe-delete` row in the profile patch, or remove the bundle. The
trash stays on disk; delete `.dsh/trash` manually once you no longer need it.
The plugin never permanently deletes user data on its own.

## Releasing

See [RELEASING.md](RELEASING.md) for the remote, CI, real-host smoke and npm publish checklist.

## License

MIT, see [LICENSE](LICENSE).
