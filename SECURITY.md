# Security model

`dsh-safe-delete-tool` changes how an agent deletes inside a DSH workspace. This
document states what it guarantees, what it does not, and where the boundary
really is.

The design follows one rule: **recoverability belongs to the delete primitive,
not to the parser.** A text guard cannot prove that a command is harmless, so
the plugin's real promise is that `delete_file` never permanently deletes user
data, and the guard is a bounded, best-effort refusal layer on top.

## Guarantees for `delete_file`

1. **The target is inside the workspace after symlink resolution.** The parent
   and non-symlink target are resolved with the platform-native `realpath`, the
   target is re-checked through that canonical path, and the result must be a
   strict descendant of the workspace. `..`, absolute paths outside the
   workspace, and symlinked parents that leave the workspace are refused with
   `PATH_OUTSIDE_WORKSPACE`. Windows NTFS alternate data streams, trailing dots
   or spaces, and 8.3 short-name aliases (`name:stream`, `.git.`, `GIT~1`) are
   refused with `PATH_ALIAS_UNSUPPORTED` before any move, so a literal check
   cannot be redirected onto `.git`, `.env` or a trash item.
2. **The workspace root is refused** (`REFUSE_WORKSPACE_ROOT`), as are paths
   containing `.git`, `.dsh` or `.env` (`PATH_PROTECTED`, with Windows aliases
   refused as `PATH_ALIAS_UNSUPPORTED`), the trash itself
   (`PATH_IN_TRASH`), and a workspace that is a filesystem root
   (`WORKSPACE_IS_FILESYSTEM_ROOT`).
3. **A non-empty directory requires `recursive: true`.**
   `RECURSIVE_FLAG_REQUIRED` is a refusal, not a default. An empty directory is
   safe without the flag.
4. **The deletion is a move into an item directory, not an unlink.** The item
   is .dsh/trash/items/<id>/ with meta.json and payload. A pending record is
   written before the move and rewritten as trashed after it. A crash between
   the two leaves a record that list_trash shows and restore_file accepts.
   Before writing, every existing component of the trash path (`.dsh`, `trash`,
   `items`) is lstat-checked and must be a real directory; a symlink (including
   a dangling one) is refused with TRASH_DIR_OUTSIDE_WORKSPACE, and a
   non-directory component with TRASH_DIR_NOT_DIRECTORY. The deepest checked
   component is resolved again after `mkdirSync`. A junction at the root path is
   caught by the per-component lstat check, and a child item directory is
   checked separately before restore. `realpath` does not detect every physical
   bind/volume mount whose resolved path still looks lexically inside the
   workspace; that remains a residual risk described below.

5. **No shared manifest.** Each item is independent, so parallel deletes and
   concurrent DSH processes cannot overwrite each other's records.
6. **A cross-volume move is copy-then-remove.** On `EXDEV`, the copy is made
   first; `cpSync` failure removes only the partial copy and leaves the source
   in place. No fallback deletes the source before the copy exists. If the copy
   succeeds but removing the source fails, the complete copy is retained as a
   pending, listable/restorable item and `TRASH_SOURCE_REMOVE_FAILED` is
   reported instead of deleting it.
7. **Ids cannot traverse.** `restore_file` accepts only ids matching the
   timestamp-plus-hex pattern, proves `items/<id>` is a real directory (not a
   symlink or junction), resolves it under the real `items/` root, and requires
   `meta.json` to be a regular file. `../`, arbitrary names, and redirected item
   directories are refused.
8. **A trash record is data, not an instruction.** Restore re-validates the
   stored path against the current workspace, refuses absolute paths and `..`
   with `TRASH_RECORD_CORRUPT`, refuses protected segments with `PATH_PROTECTED`,
   refuses Windows ADS/8.3 aliases with `TRASH_RECORD_CORRUPT`, and refuses paths
   inside the trash. It creates missing parents component by component and
   canonicalizes each existing ancestor, so a symlinked or short-name ancestor
   cannot move the boundary. `meta.json` and a 1.x `manifest.json` are read only
   when they are regular files, never through a symlink. On Windows, backslashes
   are normalized before the checks.
9. **Overwrite archives, never unlinks.** With `overwrite: true` the occupant
   is moved to the trash and its new `trash_id` is returned. Without it the
   restore fails with `DESTINATION_EXISTS`.
10. **Nothing prunes the trash.** There is no retention window, background
    cleanup or `empty_trash` path. The plugin never permanently removes user
    data; the only `rmSync` calls remove its own bookkeeping after a restorable
    move, or a partial copy after a failed cross-volume move. When the copy
    succeeds but the source cannot be removed, the complete copy is kept, not
    removed.
11. **A 1.x trash is adopted, not ignored.** A listing shows its records from
    `manifest.json`; the first mutation turns flat `items/<id>__name` archives
    into item directories. Adoption validates that `trashRelPath` stays inside
    `items/` without aliases or symlink escapes, writes a pending record before
    the move, removes an empty item directory on failure, repairs a payload that
    landed before its meta write, and keeps the legacy record visible for retry,
    so an upgrade does not strand recoverable files.

## Sandbox mode

`delete_file` and `restore_file` move files with `node:fs`, outside the Harness
filesystem fence (`ctx.fs`). Both therefore resolve the same per-call
`ctx.sandboxPolicy` the fence consumes and refuse a `read-only` session
(`SANDBOX_READ_ONLY`). The deletion jail is the policy's `workspaceRoot` (the
immutable session workspace), with the session header cwd as the fallback; the
mutable working-directory service is used only when neither exists. A `cd`
therefore cannot move the jail outside the `workspace-write` fence. The gate
fails closed (`SANDBOX_POLICY_UNAVAILABLE`) when the policy service exists but
exposes no `resolve()`, when resolving throws, or when it returns a mode this
plugin does not know; a composition without the policy service is not gated,
because the plugin must not require a service the host may not mount.
`list_trash` and a `dry_run` preview never mutate and stay available;
`list_trash` does not create or migrate the trash; an existing 1.x trash is
shown from its manifest and adopted by the next mutation. A call with no session working directory is refused
(`WORKSPACE_UNAVAILABLE`) rather than jailed to the Host process directory.

The gate follows the policy service, not a confining `ctx.fs` backend: a
composition that mounts `dsh-sandbox-policy` without a confining filesystem
backend still has its configured mode enforced for these two tools, and only
for them.

## Guarantees for the guard

12. **Classification is by schema shape.** A tool with a string `command`
    parameter is treated as a shell; a tool with a string `code` parameter is
    treated as a program; a tool with a string `text` parameter together with
    `sessionId`/`submit` is treated as typed terminal input. This covers the
    shipped `standard`, `ptc`, `minimal` and `cordis` presets without a
    per-preset name list, and the optional terminal bundle. `apply_patch` is
    recognized by name, and a `*** Delete File:` hunk is refused with
    `PATCH_DELETE`.
13. **A PTC program is checked for more than direct `fs` calls.** A call to a
    bound shell tool with a deleting command (`pwsh({ command: "rm -rf" })`),
    a `child_process`/`execa`/`Deno.Command`/`Bun.spawn` literal, and a nested
    `run_code` are analyzed as well; bare and quoted object keys are both read.
    Module aliases from static `import`, dynamic `import`, `require`,
    `createRequire`, `fs.promises`, multi-property destructuring, and method
    aliases are followed, and literal/one-sided command concatenation or dynamic
    templates are refused. Nested programs stop at 2 levels. A computed key
    (`pwsh({ ["command"]: ... })`) remains outside the lexical scanner.
14. **Every string argument of a shell tool is scanned**, except metadata keys
    (`description`, `workdir`, `justification`, `timeoutMs`, `env`, ...). This
    closes the sibling-parameter channel: `wsl(command: "bash", stdin: "rm -rf x")`
    is refused.
15. **A refusal is monotonic.** `tools/pre-execute` returns a guided denial
    for a recognized deletion even when another listener returns `ask`, and the
    synchronous `tools.guard` repeats the analysis after approval policy
    resolves. Another plugin's `ask` plus a user approval cannot reopen the
    hole, a non-deletion keeps the other listener's decision, and a stricter
    deny/cancel is preserved.
16. **Uninspectable payloads fail closed**: a command over 64 KB, a nested
    payload over 3 levels, an unterminated quote or heredoc, an undecodable
    PowerShell `-EncodedCommand`, a shell that reads its program from a pipe,
    redirection or process substitution, a command-position `$(...)`/backtick
    substitution, a dynamic `find -exec` command, a PowerShell
    `scriptblock::Create` payload, and a command name built at runtime are all
    refused. `find -exec` wrappers, wrapper option values, cmd caret escapes and
    PowerShell object `Delete` calls are refused rather than assumed harmless.
17. **The checks do not depend on the Host filesystem.** The guard reads only
    the tool arguments; it never opens a path. That is why it is safe to run
    synchronously in `tools.guard` and why a permission failure cannot change
    its verdict.

## Non-guarantees and residual risks

18. **The guard is not a security boundary.** A shell is Turing-complete. A
    determined actor can delete through a script file (`bash deploy.sh`,
    `pwsh -File build.ps1`, `python main.py`), a runtime-built string
    (`$cmd = 'Remove-Item'; & $cmd x`), a downloaded binary, a computed
    property (`fs['rmSync']`, `tools['pwsh']`), aliased optional chaining, an
    aliased function, a deletion method reached through an object or wrapper
    (`repo.rm()` where `repo.rm` is `fs.rmSync`), a local helper that reaches a
    deletion through an alias, or native code. None of these is claimed to be
    blocked.
19. **Script files are not read.** This is deliberate: reading and parsing
    arbitrary scripts from a synchronous guard is a second, weaker parser with
    its own failure modes. MiniMax Code solves the same problem with an
    execution-layer `rm` shim; DSH plugins have no equivalent hook. The honest
    answer is to state the boundary, not to grow a scanner.
20. **Not every data-loss command is covered.** `mkfs`, `dd of=/dev/...`,
    `git reset --hard`, `git checkout -- <path>`, `git stash drop`, in-place
    editors and `>` truncation are outside the scope of this plugin. It is a
    deletion plugin, not a general command firewall.
21. **Protected segments are refused, not sandboxed.** `.git`, `.dsh` and
    `.env` cannot be deleted through `delete_file`; Windows ADS and 8.3
    short-name aliases are refused with `PATH_ALIAS_UNSUPPORTED` rather than
    followed. A shell command that writes or modifies them is not blocked
    (writing is not deletion).
22. **The trash is inside the workspace.** Anyone who can delete
    `.dsh/trash` outside DSH can still destroy recoverable items; the plugin
    does not protect its own storage from the operating system or the user.
23. **Typed terminal input is checked per call.** A command split across
    several `terminal_send` / `wsl-term` calls is not reconstructed; only the
    text present in one call is analyzed.
24. **CLI deletion tools and package scripts are not recognized.**
    `npx rimraf dist`, `del-cli`, `fd -x rm`, a `clean` script in `package.json`
    or a `make clean` target deletes through a program this layer never reads,
    exactly like a script file. They are allowed.

25. **A symlink payload restore keeps a narrow race.** A file payload is
    hard-linked into place (and a cross-volume fallback copies to a temporary
    sibling before renaming), so an existing file is never replaced silently. A
    directory payload uses `rename` after an `lstat` occupancy check, where the
    only thing a race can replace is an empty directory. A symlink payload uses
    the same `rename`, so a file created in that narrow window can be replaced;
    this is an accepted race, not a silent overwrite path.
26. **Mount points and check/use races remain.** `realpath`, per-component
    `lstat`, and item-directory checks reject symlinks and junctions that change
    the logical path, but Node's path API cannot prove that a directory is not a
    Linux bind mount or another physical mount whose resolved path still looks
    inside the workspace. A concurrent process can also replace an ancestor
    between validation and the subsequent filesystem call. These are residual
    risks under the stated fallible-model threat model, not claims of a
    syscall-level sandbox.


## Threat model

The intended failure is a **fallible model**, not an adversary: a path typo, a
recursive delete aimed one directory too high, a generated cleanup command.
For that failure, moving the target into the trash is the reliable fix, and the
guard is a cheap reminder that `delete_file` exists.

A hard boundary needs DSH's sandbox and approval policy, or an OS-level
mechanism. Do not treat this plugin as a sandbox escape boundary.

## Reporting

This is a local, MIT-licensed plugin. Report a bypass with the exact tool call,
the observed verdict and the expected behavior; a reproduction that uses a
script file or runtime-built string is a known limitation, not a new finding.
