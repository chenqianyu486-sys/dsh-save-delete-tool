// The workspace jail and path arithmetic.
//
// The rule is not "the string starts with the workspace path". Every path is
// resolved through its parent's realpath, and the result must still be a strict
// descendant of the workspace before anything moves. The workspace root itself,
// protected segments, the trash and filesystem roots are refused separately,
// because a prefix check alone does not cover them.

import { lstatSync, mkdirSync, realpathSync, statSync } from 'node:fs'
import path from 'node:path'
import { fail, isFsError } from './errors.js'

const IS_WINDOWS = process.platform === 'win32'

/** Segments that may never be deleted through this plugin. */
export const PROTECTED_SEGMENTS = new Set(['.git', '.dsh', '.env'])

/** The trash lives here, relative to the workspace root. */
export const TRASH_RELATIVE = '.dsh/trash'

/** Every component the plugin touches, including the item directory. */
const TRASH_SEGMENTS = ['.dsh', 'trash', 'items']

/** `\\?\C:\x` and `\\?\UNC\server\share` are the same paths as their plain form. */
function stripLongPrefix(value) {
  if (!value.startsWith('\\\\?\\')) return value
  const rest = value.slice(4)
  return rest.startsWith('UNC\\') ? `\\\\${rest.slice(4)}` : rest
}

/** A path normalized for equality and containment, case-folded on Windows. */
function comparable(value) {
  const resolved = stripLongPrefix(path.resolve(value)).replace(/[\\/]+$/, '')
  return IS_WINDOWS ? resolved.toLowerCase() : resolved
}

/** Convert a native relative path to the `/` form stored in trash records. */
export function toPosix(value) {
  return value.split(path.sep).join('/')
}

/** Convert a stored `/` relative path back to a native path. */
export function fromPosix(value) {
  return value.split('/').join(path.sep)
}

/** True when both paths name the same location on this platform. */
export function samePath(left, right) {
  return comparable(left) === comparable(right)
}

/** True only for a strict descendant; the parent itself does not count. */
export function isStrictlyInside(parent, child) {
  const relative = path.relative(comparable(parent), comparable(child))
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)
}

/** True for the parent itself or any descendant. */
export function isInsideOrEqual(parent, child) {
  return samePath(parent, child) || isStrictlyInside(parent, child)
}

/** Is this a filesystem root (`/`, `C:\`, `\\server\share\`)? */
export function isFilesystemRoot(directory) {
  const resolved = path.resolve(stripLongPrefix(directory))
  return path.parse(resolved).root === resolved
}

/** Fetch an optional host service without throwing when it is absent. */
export function safeService(ctx, name) {
  try {
    return typeof ctx?.get === 'function' ? ctx.get(name) : undefined
  } catch {
    return undefined
  }
}

export function realpathNative(value) {
  const resolve = typeof realpathSync.native === 'function' ? realpathSync.native : realpathSync
  return stripLongPrefix(resolve(value))
}

function failFs(label, error, target) {
  if (isFsError(error, ['ENOENT'])) fail('PATH_NOT_FOUND', `${label}: "${target}" does not exist.`)
  if (isFsError(error, ['EACCES', 'EPERM'])) fail('PATH_ACCESS_DENIED', `${label}: permission denied for "${target}".`)
  const message = error instanceof Error ? error.message : String(error)
  fail('FILESYSTEM_ERROR', `${label}: "${target}": ${message}`, { cause: error })
}

/**
 * The sandbox policy's workspace root for this call, when the service exists.
 *
 * This is the immutable session workspace the filesystem fence and the shell
 * runner use. The working-directory service is deliberately not consulted
 * first: it is the mutable cd target, and using it as the deletion jail would
 * let a cd move the target outside the sandbox boundary.
 *
 * @param {any} ctx - plugin context.
 * @param {any} exec - tool run context.
 */
function sandboxWorkspaceRoot(ctx, exec) {
  const policy = safeService(ctx, 'sandboxPolicy')
  if (policy === undefined || typeof policy.resolve !== 'function') return ''
  const session = exec?.agent?.session
  if (session === undefined) return ''
  try {
    const root = policy.resolve({ session })?.workspaceRoot
    return typeof root === 'string' && root.trim() !== '' ? root.trim() : ''
  } catch {
    // A broken policy is handled by the mutation gate; here it means no root.
    return ''
  }
}

/**
 * Resolve the session workspace for one tool call.
 *
 * The sandbox policy's workspace root is authoritative because that is the
 * boundary the filesystem fence uses. A session header is the fallback for
 * hosts without the policy service, and the mutable working-directory service
 * is only the last resort. When none names a directory the call is refused:
 * guessing the Host process directory would put the deletion jail on the
 * installation folder, which nobody chose.
 *
 * @param {any} ctx - plugin context.
 * @param {any} exec - tool run context.
 * @returns {Promise<{ root: string, sessionId: string }>}
 */
export async function resolveWorkspace(ctx, exec) {
  let candidate = ''
  const workingDirectory = safeService(ctx, 'workingDirectory')

  candidate = sandboxWorkspaceRoot(ctx, exec)
  if (candidate === '') {
    const headerCwd = exec?.agent?.session?.header?.cwd
    if (typeof headerCwd === 'string' && headerCwd.trim() !== '') candidate = headerCwd.trim()
  }
  if (candidate === '' && exec?.agent !== undefined && workingDirectory !== undefined) {
    try {
      if (typeof workingDirectory.ensure === 'function') {
        candidate = await workingDirectory.ensure(exec.agent, exec.signal)
      } else if (typeof workingDirectory.get === 'function' && exec.agent.session !== undefined) {
        candidate = workingDirectory.get(exec.agent.session)
      }
    } catch {
      // A broken service leaves the call without a workspace.
    }
  }
  if (typeof candidate !== 'string' || candidate.trim() === '') {
    fail(
      'WORKSPACE_UNAVAILABLE',
      'This call has no session working directory, so there is no workspace to jail the deletion to. ' +
        'Call the tool from an agent session whose project folder is open, and retry.',
    )
  }

  const absolute = path.resolve(stripLongPrefix(candidate))
  let info
  try {
    info = statSync(absolute)
  } catch (error) {
    failFs('Cannot use the workspace', error, absolute)
  }
  if (!info.isDirectory()) fail('WORKSPACE_NOT_DIRECTORY', `The workspace path "${absolute}" is not a directory.`)

  let root
  try {
    root = realpathNative(absolute)
  } catch (error) {
    failFs('Cannot resolve the workspace', error, absolute)
  }
  if (isFilesystemRoot(root)) {
    fail(
      'WORKSPACE_IS_FILESYSTEM_ROOT',
      `The workspace is the filesystem root "${root}". Refusing to delete there: one path typo could erase a whole disk. ` +
        'Open a project folder as the workspace instead.',
    )
  }

  return { root, sessionId: String(exec?.agent?.session?.id ?? exec?.agent?.id ?? '') }
}

/** The absolute trash directory for a workspace; always strictly inside it. */
export function trashRootFor(root) {
  return path.join(root, ...TRASH_RELATIVE.split('/'))
}

/**
 * Refuse a trash path that leaves the workspace.
 *
 * Every existing component is lstat-checked, so a symlink (including a dangling
 * one that existsSync would report as absent) is refused instead of being
 * followed by mkdirSync. The final realpath check also catches junctions and
 * mount points that are not reported as symbolic links.
 */
export function assertTrashRoot(root) {
  const trashRoot = trashRootFor(root)
  let current = root
  for (const segment of TRASH_SEGMENTS) {
    current = path.join(current, segment)
    let info
    try {
      info = lstatSync(current)
    } catch (error) {
      if (isFsError(error, ['ENOENT'])) return trashRoot
      failFs('Cannot resolve the trash directory', error, current)
    }
    if (info.isSymbolicLink()) {
      fail(
        'TRASH_DIR_OUTSIDE_WORKSPACE',
        `The trash directory "${trashRoot}" is redirected by the symbolic link "${current}". ` +
          'Refusing to follow it; remove the link or use a real .dsh directory.',
      )
    }
    if (!info.isDirectory()) {
      fail(
        'TRASH_DIR_NOT_DIRECTORY',
        `The trash directory "${trashRoot}" has a non-directory component "${current}".`,
      )
    }
  }
  let real
  try {
    // `current` is the deepest checked component (items). Resolving it, not
    // just trashRoot, catches a mount point or a link that appeared after the
    // per-segment lstat.
    real = realpathNative(current)
  } catch (error) {
    failFs('Cannot resolve the trash directory', error, current)
  }
  if (!isInsideOrEqual(root, real)) {
    fail(
      'TRASH_DIR_OUTSIDE_WORKSPACE',
      `The trash directory "${trashRoot}" resolves outside the workspace "${root}". ` +
        'Remove the link or use a workspace without a redirected .dsh directory.',
    )
  }
  return trashRoot
}

function assertNotProtected(relative) {
  const parts = relative.split('/')
  for (const part of parts) {
    if (PROTECTED_SEGMENTS.has(part.toLowerCase())) {
      fail(
        'PATH_PROTECTED',
        `Refusing to delete "${relative}": it contains the protected path segment "${part}".`,
      )
    }
  }
}

/**
 * True when a single path segment uses a Windows alias form that makes a literal
 * check see a different object: NTFS alternate data streams (name:stream),
 * trailing dots or spaces (which Win32 strips), or 8.3 short names (GIT~1).
 */
export function isWindowsAliasSegment(part) {
  if (part.includes(':') || /[. ]$/.test(part)) return true
  const dot = part.indexOf('.')
  if (dot !== -1 && part.indexOf('.', dot + 1) !== -1) return false
  const stem = dot === -1 ? part : part.slice(0, dot)
  const ext = dot === -1 ? '' : part.slice(dot + 1)
  return stem.length > 0 && stem.length <= 8 && ext.length <= 3 && /~\d+$/.test(stem)
}

/**
 * Refuse Windows path aliases that make a literal check see a different object:
 * NTFS alternate data streams (name:stream), trailing dots/spaces, and 8.3 short names (GIT~1).
 */
export function assertNoWindowsAlias(relative, code = 'PATH_ALIAS_UNSUPPORTED') {
  if (!IS_WINDOWS) return
  for (const part of relative.split('/')) {
    if (part.includes(':')) {
      fail(code, 'Refusing "' + relative + '": Windows alternate data stream paths are not supported.')
    }
    if (/[. ]$/.test(part)) {
      fail(code, 'Refusing "' + relative + '": Windows trailing dot or space paths are not supported.')
    }
    if (isWindowsAliasSegment(part)) {
      fail(code, 'Refusing "' + relative + '": Windows 8.3 short-name paths are not supported.')
    }
  }
}

function realDirectory(directory) {
  let info
  try {
    info = statSync(directory)
  } catch (error) {
    failFs('Cannot resolve the parent directory', error, directory)
  }
  if (!info.isDirectory()) fail('PATH_NOT_DIRECTORY', `"${directory}" is not a directory.`)
  try {
    return realpathNative(directory)
  } catch (error) {
    failFs('Cannot resolve the parent directory', error, directory)
  }
}

/**
 * Prove that a model-supplied path is a real, deletable object inside the
 * workspace. Returns the canonical target and the workspace-relative path that
 * a trash record must store.
 *
 * @param {{ root: string, input: string }} options
 */
export function inspectTarget({ root, input }) {
  if (typeof input !== 'string' || input.trim() === '') {
    fail('INVALID_PATH', '`path` must be a non-empty string.')
  }
  if (input.includes('\u0000')) fail('INVALID_PATH', '`path` contains a NUL byte.')

  const normalizedInput = IS_WINDOWS ? stripLongPrefix(input) : input
  if (IS_WINDOWS && /^[/\\]{2}\.[/\\]/.test(normalizedInput)) {
    fail('PATH_OUTSIDE_WORKSPACE', `Refusing to delete "${input}": Win32 device paths are not supported.`)
  }

  const trashRoot = trashRootFor(root)
  const absolute = path.resolve(root, normalizedInput)
  if (samePath(absolute, root)) {
    fail('REFUSE_WORKSPACE_ROOT', 'Refusing to delete the workspace root. Target a file or a subdirectory instead.')
  }
  if (!isStrictlyInside(root, absolute)) {
    fail('PATH_OUTSIDE_WORKSPACE', `Refusing to delete "${input}": it is outside the workspace "${root}".`)
  }

  const relative = toPosix(path.relative(root, absolute))
  assertNotProtected(relative)
  assertNoWindowsAlias(relative)
  if (isInsideOrEqual(trashRoot, absolute)) {
    fail('PATH_IN_TRASH', `Refusing to delete "${relative}": it is inside the trash.`)
  }

  const parentReal = realDirectory(path.dirname(absolute))
  const canonical = path.join(parentReal, path.basename(absolute))
  if (samePath(canonical, root)) {
    fail('REFUSE_WORKSPACE_ROOT', 'Refusing to delete the workspace root. Target a file or a subdirectory instead.')
  }
  if (!isStrictlyInside(root, canonical)) {
    fail(
      'PATH_OUTSIDE_WORKSPACE',
      `Refusing to delete "${input}": its parent resolves outside the workspace "${root}".`,
    )
  }
  // A symlinked parent can resolve into `.git` or `.dsh` even when the literal
  // path does not contain those segments. Re-check the canonical path.
  const canonicalRelative = toPosix(path.relative(root, canonical))
  assertNotProtected(canonicalRelative)
  assertNoWindowsAlias(canonicalRelative)
  if (isInsideOrEqual(trashRoot, canonical)) {
    fail('PATH_IN_TRASH', `Refusing to delete "${canonicalRelative}": it is inside the trash.`)
  }

  let info
  try {
    info = lstatSync(canonical)
  } catch (error) {
    failFs('Cannot inspect the target', error, canonicalRelative)
  }

  if (info.isSymbolicLink()) {
    // A symlink is archived as a link, not followed. Its parent was already
    // canonicalized, so deleting the link itself is safe.
    return { absolute: canonical, relative: canonicalRelative, kind: 'symlink' }
  }

  // 8.3 short names and other reparse aliases are not expanded by the plain
  // realpath used above. Resolve the target itself with the native API so a
  // literal "GIT~1" cannot hide the protected ".git" directory.
  let resolved
  try {
    resolved = realpathNative(canonical)
  } catch (error) {
    failFs('Cannot resolve the target', error, canonicalRelative)
  }
  if (samePath(resolved, root)) {
    fail('REFUSE_WORKSPACE_ROOT', 'Refusing to delete the workspace root. Target a file or a subdirectory instead.')
  }
  if (!isStrictlyInside(root, resolved)) {
    fail(
      'PATH_OUTSIDE_WORKSPACE',
      `Refusing to delete "${input}": it resolves outside the workspace "${root}".`,
    )
  }
  const resolvedRelative = toPosix(path.relative(root, resolved))
  assertNotProtected(resolvedRelative)
  assertNoWindowsAlias(resolvedRelative)
  if (isInsideOrEqual(trashRoot, resolved)) {
    fail('PATH_IN_TRASH', `Refusing to delete "${resolvedRelative}": it is inside the trash.`)
  }

  return {
    absolute: resolved,
    relative: resolvedRelative,
    kind: info.isDirectory() ? 'directory' : 'file',
  }
}

/**
 * Re-validate a path stored in a trash record before restoring it. The record is
 * data on disk, not a trusted instruction, so it goes through the same jail.
 *
 * @param {{ root: string, storedPath: string }} options
 */
export function inspectRestorePath({ root, storedPath }) {
  if (typeof storedPath !== 'string' || storedPath === '') {
    fail('TRASH_RECORD_CORRUPT', 'The trash record has no original path.')
  }
  // Records are written with POSIX separators. On Windows a hand-edited record
  // can use backslashes to hide a protected segment from the split below while
  // path.resolve still treats it as a separator; normalize before validating.
  const recordPath = IS_WINDOWS ? storedPath.replaceAll('\\', '/') : storedPath
  if (/^[A-Za-z]:/.test(recordPath) || recordPath.startsWith('/') || recordPath.startsWith('\\')) {
    fail('TRASH_RECORD_CORRUPT', `The trash record stores an absolute path ("${storedPath}"); refusing to restore it.`)
  }
  const parts = recordPath.split('/')
  if (parts.some((part) => part === '' || part === '.' || part === '..')) {
    fail('TRASH_RECORD_CORRUPT', `The trash record stores an invalid path ("${storedPath}"); refusing to restore it.`)
  }
  assertNotProtected(recordPath)
  assertNoWindowsAlias(recordPath, 'TRASH_RECORD_CORRUPT')
  const destination = path.resolve(root, fromPosix(recordPath))
  if (!isStrictlyInside(root, destination)) {
    fail('TRASH_RECORD_CORRUPT', `The trash record points outside the workspace ("${storedPath}").`)
  }
  if (isInsideOrEqual(trashRootFor(root), destination)) {
    fail('TRASH_RECORD_CORRUPT', `The trash record points into the trash ("${storedPath}").`)
  }
  return destination
}

function validateExistingParentComponent(root, next) {
  let info
  try {
    info = lstatSync(next)
  } catch (error) {
    if (isFsError(error, ['ENOENT'])) return null
    failFs('Cannot resolve the restore parent', error, next)
  }
  if (!info.isSymbolicLink() && !info.isDirectory()) {
    fail('PATH_NOT_DIRECTORY', `"${next}" is not a directory.`)
  }
  let real
  try {
    real = realpathNative(next)
  } catch (error) {
    failFs('Cannot resolve the restore parent', error, next)
  }
  let realInfo
  try {
    realInfo = statSync(real)
  } catch (error) {
    failFs('Cannot resolve the restore parent', error, real)
  }
  if (!realInfo.isDirectory()) fail('PATH_NOT_DIRECTORY', `"${next}" is not a directory.`)
  if (!isInsideOrEqual(root, real)) {
    fail('PATH_OUTSIDE_WORKSPACE', `Refusing to restore through "${next}": it points outside the workspace.`)
  }
  assertNotProtected(toPosix(path.relative(root, real)))
  return real
}

/**
 * Validate existing ancestor directories of a restore destination without
 * creating any missing directories.
 *
 * @param {string} root
 * @param {string} destination
 */
export function assertSafeExistingParents(root, destination) {
  const parent = path.dirname(destination)
  const relative = path.relative(root, parent)
  if (relative === '') return

  let current = root
  for (const segment of relative.split(path.sep)) {
    if (segment === '' || segment === '.') continue
    const next = path.join(current, segment)
    const real = validateExistingParentComponent(root, next)
    if (real === null) return
    current = real
  }
}

/**
 * Create the missing parents of a restore destination while proving that every
 * existing ancestor still resolves inside the workspace. Creating a directory
 * through a symlink that leaves the workspace would move the boundary, so each
 * component is checked before it is used.
 *
 * @param {string} root
 * @param {string} destination
 */
export function ensureSafeParent(root, destination) {
  const parent = path.dirname(destination)
  const relative = path.relative(root, parent)
  if (relative === '') return

  let current = root
  for (const segment of relative.split(path.sep)) {
    if (segment === '' || segment === '.') continue
    const next = path.join(current, segment)
    const real = validateExistingParentComponent(root, next)
    if (real === null) {
      try {
        mkdirSync(next)
      } catch (mkdirError) {
        failFs('Cannot create the restore parent', mkdirError, next)
      }
      current = next
      continue
    }
    current = real
  }
}
