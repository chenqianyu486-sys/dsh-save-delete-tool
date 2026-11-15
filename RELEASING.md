# Releasing dsh-safe-delete-tool

This file records the release steps that are outside the package itself. The
package is a DSH bundle, not a standalone app; npm publication and plugin-market
publication are separate decisions.

## Before publishing

1. Run the tests and inspect the package:
       npm test
       npm pack --dry-run
2. Confirm the version in package.json, index.js VERSION and CHANGELOG agree.
3. Confirm the repository URL in package.json points at the real remote.

## GitHub

The local repository is initialized on branch main and tagged v2.0.3. The
intended remote is:

    https://github.com/chenqianyu486-sys/dsh-save-delete-tool.git

The remote does not exist yet. Create it, then push:

    git remote add origin https://github.com/chenqianyu486-sys/dsh-save-delete-tool.git
    git push -u origin main
    git push origin v2.0.3

The CI workflows in .github/workflows run on push and pull request. The release
workflow runs on a v* tag and uploads the npm tarball as an artifact. It does
not publish to npm automatically.

## Real-host smoke

A full DSH host is not installed by CI. Before a public release, load the bundle
in a desktop profile and run:

- delete_file -> list_trash -> restore_file on a scratch file;
- a workspace-write session with a redirected .dsh/trash/items (must refuse);
- a PTC program with pwsh({ command: "Remove-Item ..." }) (must refuse);
- a harmless command whose text contains rm (must pass);
- reload/restart behavior: a stale module must show its version in a refusal.

The plugin-manager page and tool card still need a visual check in the desktop
app or in an authenticated Web session.

## npm

After the remote/CI are green and the real-host smoke is recorded:

    npm publish

The package name dsh-safe-delete-tool is currently unused on npm. dsh-safe-delete
is a different Apache-2.0 package; do not publish under that name.

## Post-publish

Install from the npm tarball in a fresh profile and repeat the three-tool
round-trip. Do not claim MiniMax-equivalent native-delete disabling; the
supported claim is recoverable deletion plus a best-effort guard.
