// The recoverable trash.
//
// One directory per deletion is the whole journal: `items/<id>/meta.json` plus
// `items/<id>/payload`. There is no shared manifest to rewrite, so two parallel
// deletes (or two DSH processes) cannot overwrite each other's records, and a
// crash leaves a self-describing item that `list_trash` can still show. The
// record is written before the move and rewritten after it, so an interrupted
// move is visible as `pending` rather than lost.
//
// Nothing here permanently deletes user data. The only `rmSync` calls remove
// this plugin's own bookkeeping after a restore, or a partial copy after a
// failed cross-volume move.

import {
  chmodSync,
  cpSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { randomBytes } from 'node:crypto'
import path from 'node:path'
import { fail, SafeDeleteError, isFsError } from './errors.js'
import {
  assertNoWindowsAlias,
  assertSafeExistingParents,
  assertTrashRoot,
  ensureSafeParent,
  inspectRestorePath,
  inspectTarget,
  isInsideOrEqual,
  isStrictlyInside,
  realpathNative,
  trashRootFor,
} from './paths.js'

const KINDS = new Set(['file', 'directory', 'symlink'])

/** Ids are time-ordered; the longer form is written by 2.x, the shorter by 1.x. */
const ID_RE = /^(?:\d{8}T\d{9}|\d{8}T\d{6})-[0-9a-f]{8}$/

/** Per-process monotonic clock so two deletes in the same millisecond stay ordered. */
let lastStamp = 0

function newId() {
  const now = Date.now()
  lastStamp = now > lastStamp ? now : lastStamp + 1
  const stamp = new Date(lastStamp).toISOString().replace(/[-:]/g, '').replace('.', '').replace('Z', '')
  return `${stamp}-${randomBytes(4).toString('hex')}`
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function validRecord(value) {
  return (
    isPlainObject(value) &&
    typeof value.id === 'string' &&
    typeof value.path === 'string' &&
    KINDS.has(value.kind) &&
    (value.status === 'pending' || value.status === 'trashed')
  )
}

function writeMeta(itemDir, record) {
  const target = path.join(itemDir, 'meta.json')
  const temporary = path.join(itemDir, 'meta.json.tmp')
  writeFileSync(temporary, `${JSON.stringify(record, null, 2)}\n`, 'utf8')
  try {
    renameSync(temporary, target)
  } catch (error) {
    if (isFsError(error, ['EEXIST', 'EPERM', 'EACCES'])) {
      rmSync(target, { force: true })
      renameSync(temporary, target)
      return
    }
    throw error
  }
}

function readRecord(itemDir, id) {
  const metaPath = path.join(itemDir, 'meta.json')
  let info
  try {
    info = lstatSync(metaPath)
  } catch (error) {
    if (isFsError(error, ['ENOENT', 'ENOTDIR'])) return null
    throw error
  }
  // A record is data written by this plugin, never an executable or a link.
  // Refuse to follow a symlinked meta.json into a directory outside the item.
  if (info.isSymbolicLink() || !info.isFile()) return null
  let text
  try {
    text = readFileSync(metaPath, 'utf8')
  } catch (error) {
    if (isFsError(error, ['ENOENT', 'ENOTDIR'])) return null
    throw error
  }
  let record
  try {
    record = JSON.parse(text)
  } catch {
    return null
  }
  if (!validRecord(record) || record.id !== id) return null
  return record
}

/**
 * Prove that one item directory is a real directory below the real items root.
 *
 * The root check in paths.js only validates `.dsh`, `trash` and `items`. A
 * junction at `items/<id>` is a separate redirect: restore would otherwise read
 * `meta.json` and move `payload` from outside the workspace. Return null when
 * the item does not exist so callers can report the normal not-found error.
 */
function assertItemDirectory(itemsRoot, itemDir) {
  let info
  try {
    info = lstatSync(itemDir)
  } catch (error) {
    if (isFsError(error, ['ENOENT', 'ENOTDIR'])) return null
    fail('TRASH_ITEM_UNREADABLE', `Cannot inspect the trash item "${itemDir}": ${error instanceof Error ? error.message : String(error)}`, {
      cause: error,
    })
  }
  if (info.isSymbolicLink()) {
    fail(
      'TRASH_ITEM_OUTSIDE_WORKSPACE',
      `The trash item "${itemDir}" is redirected by a symbolic link or junction. Refusing to follow it.`,
    )
  }
  if (!info.isDirectory()) {
    fail('TRASH_ITEM_INVALID', `The trash item "${itemDir}" is not a directory.`)
  }

  let realRoot
  let realItem
  try {
    realRoot = realpathNative(itemsRoot)
    realItem = realpathNative(itemDir)
  } catch (error) {
    fail('TRASH_ITEM_UNREADABLE', `Cannot resolve the trash item "${itemDir}": ${error instanceof Error ? error.message : String(error)}`, {
      cause: error,
    })
  }
  if (!isStrictlyInside(realRoot, realItem)) {
    fail(
      'TRASH_ITEM_OUTSIDE_WORKSPACE',
      `The trash item "${itemDir}" resolves outside the items directory. Refusing to follow it.`,
    )
  }
  return itemDir
}

/** Wrap raw Node filesystem errors into SafeDeleteError with stable codes. */
function toSafeFsError(label, error, target) {
  if (error instanceof SafeDeleteError) return error
  if (isFsError(error, ['ENOENT'])) {
    return new SafeDeleteError('PATH_NOT_FOUND', `${label}: "${target}" does not exist.`, { cause: error })
  }
  if (isFsError(error, ['EACCES', 'EPERM'])) {
    return new SafeDeleteError('PATH_ACCESS_DENIED', `${label}: permission denied for "${target}".`, { cause: error })
  }
  if (isFsError(error, ['EBUSY', 'EMFILE', 'ENFILE', 'ETXTBSY'])) {
    return new SafeDeleteError('PATH_BUSY', `${label}: "${target}" is busy or locked.`, { cause: error })
  }
  const message = error instanceof Error ? error.message : String(error)
  return new SafeDeleteError('FILESYSTEM_ERROR', `${label}: "${target}": ${message}`, { cause: error })
}

function wrapFsError(label, error, target) {
  throw toSafeFsError(label, error, target)
}

/**
 * Validate and resolve a 1.x `trashRelPath` under `items/`, refusing escapes,
 * Windows aliases, and symlinked subdirectories inside `items/`.
 */
function resolveLegacyArchive(trashRoot, itemsRoot, rawRelative) {
  if (typeof rawRelative !== 'string') return null
  const relative = rawRelative.replaceAll('\\', '/')
  if (relative === '' || relative.startsWith('/') || /^[A-Za-z]:/.test(relative)) return null
  const parts = relative.split('/')
  if (parts.some((part) => part === '' || part === '.' || part === '..')) return null
  if (parts[0] !== 'items' || parts.length < 2) return null
  try {
    assertNoWindowsAlias(relative, 'TRASH_RECORD_CORRUPT')
  } catch {
    return null
  }
  const archive = path.join(trashRoot, ...parts)
  let exists = false
  try {
    exists = existsAt(archive)
  } catch {
    return null
  }
  if (exists) {
    try {
      const realItems = realpathNative(itemsRoot)
      const realParent = realpathNative(path.dirname(archive))
      if (!isInsideOrEqual(realItems, realParent)) return null
    } catch {
      return null
    }
  }
  return archive
}

/** Read a 1.x manifest only when it is a regular file, never through a symlink. */
function readLegacyManifest(trashRoot) {
  const manifestPath = path.join(trashRoot, 'manifest.json')
  let info
  try {
    info = lstatSync(manifestPath)
  } catch (error) {
    if (isFsError(error, ['ENOENT', 'ENOTDIR'])) return null
    throw error
  }
  if (info.isSymbolicLink() || !info.isFile()) return null
  try {
    return JSON.parse(readFileSync(manifestPath, 'utf8'))
  } catch {
    return null
  }
}


/**
 * Move a file or a directory; cross-volume moves are copied first.
 *
 * If the copy succeeds but the source cannot be removed, the copy is the only
 * complete version: keep it and report TRASH_SOURCE_REMOVE_FAILED. The caller
 * must not delete the item directory in that case. The operations parameter is
 * a test seam; production callers use the node:fs bindings above.
 */
export function movePath(source, target, operations = { renameSync, cpSync, rmSync }) {
  try {
    operations.renameSync(source, target)
    return
  } catch (error) {
    if (!isFsError(error, ['EXDEV'])) throw error
  }
  operations.cpSync(source, target, { recursive: true, dereference: false, force: false, errorOnExist: true })
  try {
    operations.rmSync(source, { recursive: true, force: true })
  } catch (error) {
    const failure = new SafeDeleteError(
      'TRASH_SOURCE_REMOVE_FAILED',
      'The target was copied into the recoverable trash, but the original could not be fully removed: ' +
        `${error instanceof Error ? error.message : String(error)}. The recoverable copy was kept.`,
      { cause: error },
    )
    failure.copyComplete = true
    throw failure
  }
}

/** Wrap a copy-complete / source-remove failure with the item id and guidance. */
function sourceRemovalFailure(error, subject, id) {
  if (error?.code !== 'TRASH_SOURCE_REMOVE_FAILED') return null
  const cause = error?.cause instanceof Error ? error.cause.message : error instanceof Error ? error.message : String(error)
  const detail = String(cause).replace(/^\[[A-Z0-9_]+\]\s*/, '')
  return new SafeDeleteError(
    'TRASH_SOURCE_REMOVE_FAILED',
    `${subject} was copied into the recoverable trash as "${id}", but the original could not be fully removed: ` +
      `${detail} The recoverable copy was kept; use list_trash and restore_file, then remove the remaining ` +
      'source manually.',
    { cause: error },
  )
}

/**
 * True when the name exists, including a dangling symbolic link: `existsSync`
 * follows links and reports a broken one as absent.
 */
function existsAt(target) {
  try {
    lstatSync(target)
    return true
  } catch (error) {
    if (isFsError(error, ['ENOENT', 'ENOTDIR'])) return false
    throw error
  }
}

/**
 * Copy a payload next to its destination and rename it into place, so a failed
 * or interrupted copy is never visible at the destination and its partial copy
 * is removed instead of being left behind.
 */
function placeByCopy(source, target) {
  const temporary = `${target}.dsh-partial-${randomBytes(4).toString('hex')}`
  try {
    cpSync(source, temporary, { recursive: true, dereference: false, force: false, errorOnExist: true })
    renameSync(temporary, target)
  } catch (error) {
    try {
      rmSync(temporary, { recursive: true, force: true })
    } catch {
      // Best effort: the partial copy is still hidden from the destination.
    }
    throw error
  }
  try {
    rmSync(source, { recursive: true, force: true })
  } catch {
    // The restored file is already in place; caller cleans up the item dir.
  }
}

export class TrashStore {
  /**
   * @param {{ root: string, move?: typeof movePath }} options - `move` is a
   *   test seam for the cross-volume failure path; production uses movePath.
   */
  constructor({ root, move = movePath }) {
    this.root = root
    this.trashRoot = trashRootFor(root)
    this.itemsRoot = path.join(this.trashRoot, 'items')
    this.move = move
  }

  /** Create the layout and adopt records written by dsh-safe-delete-tool 1.x. */
  ensureLayout() {
    assertTrashRoot(this.root)
    try {
      mkdirSync(this.itemsRoot, { recursive: true })
    } catch (error) {
      wrapFsError('Cannot create the trash directory', error, this.itemsRoot)
    }
    // Re-check after mkdir: the first pass can stop at a missing `items`, and
    // a symlink/junction must not survive the create. No payload is moved
    // before this second check passes.
    assertTrashRoot(this.root)
    const ignore = path.join(this.trashRoot, '.gitignore')
    try {
      if (!existsAt(ignore)) {
        try {
          writeFileSync(ignore, '# dsh-safe-delete-tool: the trash is never committed.\n*\n', {
            encoding: 'utf8',
            flag: 'wx',
          })
        } catch (error) {
          if (!isFsError(error, ['EEXIST'])) throw error
        }
      }
    } catch (error) {
      wrapFsError('Cannot initialize the trash ignore file', error, ignore)
    }
    this.#migrateLegacy()
  }

  /** True only for an item directory that already holds a complete item. */
  #itemIsRecoverable(id) {
    const itemDir = path.join(this.itemsRoot, id)
    try {
      if (assertItemDirectory(this.itemsRoot, itemDir) === null) return false
    } catch {
      return false
    }
    let record
    try {
      record = readRecord(itemDir, id)
    } catch {
      return false
    }
    return record !== null && existsAt(path.join(itemDir, 'payload'))
  }

  /**
   * Read 1.x records without migrating them. Listing must not write, so a
   * legacy archive is shown from its manifest until a mutation adopts it.
   */
  #legacyRecords() {
    const manifest = readLegacyManifest(this.trashRoot)
    if (manifest === null) return []
    if (!isPlainObject(manifest) || !Array.isArray(manifest.items)) return []
    const records = []
    for (const item of manifest.items) {
      if (!isPlainObject(item) || item.state !== 'trashed') continue
      const id = typeof item.id === 'string' ? item.id : ''
      if (!ID_RE.test(id) || this.#itemIsRecoverable(id)) continue
      const archive = resolveLegacyArchive(this.trashRoot, this.itemsRoot, item.trashRelPath)
      if (archive === null) continue
      const itemDir = path.join(this.itemsRoot, id)
      if (!existsAt(archive) && !existsAt(path.join(itemDir, 'payload'))) continue
      records.push({
        version: 1,
        id,
        path: String(item.originalRelPath ?? '').replaceAll('\\', '/'),
        kind: KINDS.has(item.kind) ? item.kind : 'file',
        entries: Number.isInteger(item.entries) ? item.entries : 0,
        reason: typeof item.reason === 'string' ? item.reason.slice(0, 500) : '',
        sessionId: typeof item.sessionId === 'string' ? item.sessionId : '',
        deletedAt: typeof item.deletedAt === 'string' ? item.deletedAt : new Date().toISOString(),
        status: 'trashed',
      })
    }
    return records
  }

  /**
   * Adopt a 1.x trash (`manifest.json` + flat `items/<id>__name` archives) into
   * item directories, so an upgrade does not strand recoverable files.
   */
  #migrateLegacy() {
    const manifest = readLegacyManifest(this.trashRoot)
    if (manifest === null) return
    if (!isPlainObject(manifest) || !Array.isArray(manifest.items)) return

    const manifestPath = path.join(this.trashRoot, 'manifest.json')
    let failed = 0
    for (const item of manifest.items) {
      try {
        if (!isPlainObject(item) || item.state !== 'trashed') continue
        const id = typeof item.id === 'string' ? item.id : ''
        if (!ID_RE.test(id)) continue
        const itemDir = path.join(this.itemsRoot, id)
        const archive = resolveLegacyArchive(this.trashRoot, this.itemsRoot, item.trashRelPath)
        if (archive === null) continue
        const payload = path.join(itemDir, 'payload')
        let existing = null
        try {
          existing = readRecord(itemDir, id)
        } catch {
          existing = null
        }
        if (existsAt(itemDir)) {
          try {
            if (assertItemDirectory(this.itemsRoot, itemDir) === null) continue
          } catch {
            failed += 1
            continue
          }
          if (existing !== null && existsAt(payload)) continue
          if (!existsAt(payload)) {
            if (!existsAt(archive)) continue
            try {
              rmSync(itemDir, { recursive: true, force: true })
            } catch {
              failed += 1
              continue
            }
          }
        }
        if (!existsAt(archive) && !existsAt(payload)) continue
        const record = {
          version: 1,
          id,
          path: String(item.originalRelPath ?? '').replaceAll('\\', '/'),
          kind: KINDS.has(item.kind) ? item.kind : 'file',
          entries: Number.isInteger(item.entries) ? item.entries : 0,
          reason: typeof item.reason === 'string' ? item.reason.slice(0, 500) : '',
          sessionId: typeof item.sessionId === 'string' ? item.sessionId : '',
          deletedAt: typeof item.deletedAt === 'string' ? item.deletedAt : new Date().toISOString(),
          status: 'trashed',
        }
        if (!existsAt(itemDir)) mkdirSync(itemDir)
        if (existsAt(payload)) {
          // A previous migration moved the payload but crashed before the meta
          // write; the payload is the complete item, so record it now.
          writeMeta(itemDir, record)
          continue
        }
        // The pending record is written before the move. A crash after the
        // move therefore leaves a listable, restorable item rather than an
        // invisible payload directory.
        writeMeta(itemDir, { ...record, status: 'pending' })
        try {
          this.move(archive, payload)
        } catch (error) {
          if (!existsAt(payload)) {
            try {
              rmSync(itemDir, { recursive: true, force: true })
            } catch {
              // Best effort; the outer catch records the failure.
            }
          }
          throw error
        }
        writeMeta(itemDir, record)
      } catch {
        failed += 1
      }
    }
    if (failed === 0) {
      try {
        renameSync(manifestPath, path.join(this.trashRoot, 'manifest.json.migrated'))
      } catch {
        // Leaving the manifest in place is harmless: adopted ids are skipped.
      }
    }
  }

  /**
   * Move one target into the trash, or report what a real call would do.
   * @param {string} input
   * @param {{ recursive: boolean, dryRun: boolean, reason: string, sessionId: string }} options
   */
  delete(input, { recursive, dryRun, reason, sessionId }) {
    const target = inspectTarget({ root: this.root, input })
    let entries = 0
    if (target.kind === 'directory') {
      try {
        entries = readdirSync(target.absolute).length
      } catch (error) {
        wrapFsError('Cannot inspect the target directory', error, target.relative)
      }
    }
    const recursiveRequired = target.kind === 'directory' && entries > 0
    const displayPath = target.relative

    if (dryRun) {
      return {
        ok: true,
        dry_run: true,
        path: displayPath,
        kind: target.kind,
        entries,
        recursive_required: recursiveRequired,
        message:
          recursiveRequired && !recursive
            ? `Dry run: \`${displayPath}\` is a non-empty directory (${entries} entries); a real call must pass \`recursive: true\`. Nothing was moved.`
            : `Dry run: \`${displayPath}\` (${target.kind}) would move to the trash. Nothing was moved.`,
      }
    }
    if (recursiveRequired && !recursive) {
      fail(
        'RECURSIVE_FLAG_REQUIRED',
        `Refusing to delete the non-empty directory "${displayPath}": pass \`recursive: true\` explicitly. ` +
          'Use `dry_run: true` first if you are not sure.',
      )
    }

    this.ensureLayout()
    const id = newId()
    const itemDir = path.join(this.itemsRoot, id)
    const record = {
      version: 1,
      id,
      path: displayPath,
      kind: target.kind,
      entries,
      reason: typeof reason === 'string' ? reason.slice(0, 500) : '',
      sessionId: typeof sessionId === 'string' ? sessionId.slice(0, 200) : '',
      deletedAt: new Date().toISOString(),
      status: 'pending',
    }
    try {
      mkdirSync(itemDir)
      writeMeta(itemDir, record)
    } catch (error) {
      wrapFsError('Cannot create the trash item', error, itemDir)
    }
    try {
      this.move(target.absolute, path.join(itemDir, 'payload'))
    } catch (error) {
      const sourceFailure = sourceRemovalFailure(error, `The target "${displayPath}"`, id)
      if (sourceFailure !== null) throw sourceFailure
      try {
        rmSync(itemDir, { recursive: true, force: true })
      } catch {
        // The move failed; cleanup is best effort and must not mask the cause.
      }
      wrapFsError('Cannot move target to the trash', error, displayPath)
    }
    try {
      writeMeta(itemDir, { ...record, status: 'trashed' })
    } catch {
      // The pending record plus the payload is already a complete item; list
      // and restore accept it. Do not report a failure for a move that landed.
    }

    return {
      ok: true,
      dry_run: false,
      path: displayPath,
      kind: target.kind,
      entries,
      trash_id: id,
      message: `Moved \`${displayPath}\` to the recoverable trash. Undo with \`restore_file({"trash_id":"${id}"})\`.`,
    }
  }

  /**
   * Undo one deletion. Re-validates the stored path against the current
   * workspace; never overwrites without `overwrite`.
   * @param {string} id
   * @param {{ overwrite: boolean, sessionId?: string }} options
   */
  restore(id, { overwrite, sessionId = '' }) {
    if (typeof id !== 'string' || !ID_RE.test(id)) {
      fail('INVALID_TRASH_ID', `"${id}" is not a valid trash id. Use \`list_trash\` to find the id.`)
    }
    this.ensureLayout()
    const itemDir = path.join(this.itemsRoot, id)
    if (!isStrictlyInside(this.itemsRoot, itemDir)) {
      fail('INVALID_TRASH_ID', `"${id}" is not a valid trash id.`)
    }
    // `items/<id>` is a separate redirect from the trash root. Validate it
    // before readRecord can follow a junction to an external meta.json/payload.
    if (assertItemDirectory(this.itemsRoot, itemDir) === null) {
      fail('TRASH_ITEM_NOT_FOUND', `No recoverable item with trash_id "${id}". Use \`list_trash\` to see what is recoverable.`)
    }
    let record
    const payload = path.join(itemDir, 'payload')
    let payloadExists = false
    try {
      record = readRecord(itemDir, id)
      if (record !== null) payloadExists = existsAt(payload)
    } catch (error) {
      wrapFsError('Cannot read the trash item', error, itemDir)
    }
    if (record === null) {
      fail('TRASH_ITEM_NOT_FOUND', `No recoverable item with trash_id "${id}". Use \`list_trash\` to see what is recoverable.`)
    }
    if (!payloadExists) {
      fail('TRASH_ITEM_INCOMPLETE', `The record for "${id}" exists but its archived file is missing; it cannot be restored.`)
    }

    const destination = inspectRestorePath({ root: this.root, storedPath: record.path })
    assertSafeExistingParents(this.root, destination)

    // Check the occupant before creating parents: a refused restore must not
    // leave empty directories behind. `existsAt` uses `lstat`, because
    // `existsSync` follows links and would miss a dangling symlink that a POSIX
    // rename would then replace.
    let occupied = false
    try {
      occupied = existsAt(destination)
    } catch (error) {
      wrapFsError('Cannot inspect the restore destination', error, record.path)
    }
    let replaced = ''
    if (occupied) {
      if (!overwrite) {
        fail(
          'DESTINATION_EXISTS',
          `Cannot restore "${record.path}": the path is occupied. Pass \`overwrite: true\` to move the current occupant into the trash first.`,
        )
      }
      replaced = this.#archiveOccupant(destination, sessionId)
    }

    try {
      ensureSafeParent(this.root, destination)
      this.#place(payload, destination)
    } catch (error) {
      const wrapped = toSafeFsError('Cannot restore the trash item', error, record.path)
      if (replaced !== '') {
        const detail = wrapped.message
          .replace(/^\[[A-Z0-9_]+\]\s*/, '')
          .replace(/\s*Nothing was moved[^.]*\./i, '')
          .trim()
        throw new SafeDeleteError(
          wrapped.code,
          `Failed to restore "${record.path}" (trash_id "${id}") after archiving the previous occupant as "${replaced}": ` +
            `${detail} Both "${id}" and "${replaced}" remain recoverable in the trash.`,
          { cause: error },
        )
      }
      throw wrapped
    }
    try {
      rmSync(itemDir, { recursive: true, force: true })
    } catch {
      // The file is already back. A stale item directory without a payload is
      // skipped by `list`; do not turn a successful restore into a failure.
    }
    return {
      ok: true,
      path: record.path,
      kind: record.kind,
      replaced_trash_id: replaced,
      message:
        replaced === ''
          ? `Restored \`${record.path}\` from the trash.`
          : `Restored \`${record.path}\`; the occupant was moved to the trash as \`${replaced}\`.`,
    }
  }

  /**
   * Move the archived payload into place without replacing something that
   * appeared since the destination was checked.
   *
   * A plain `rename` replaces an existing file on POSIX, so a file payload is
   * hard-linked into place first: `link` fails with `EEXIST` instead of
   * overwriting. Any other link failure falls through to a rename that
   * re-checks the destination immediately before it runs, so a permission
   * failure cannot turn into a silent replace either. A cross-volume fallback
   * copies to a sibling temporary name and renames that into place, so a failed
   * copy never leaves a half-written file at the destination.
   */
  #place(payload, destination) {
    const info = lstatSync(payload)
    if (info.isFile()) {
      // Preserve the original mode across the hard-link restore. `#dropPayload`
      // must temporarily clear the Windows read-only attribute to unlink the
      // archive copy; without restoring the captured mode that chmod would also
      // rewrite the restored file (and every other hard link to the inode).
      const mode = info.mode & 0o7777
      let linked = false
      try {
        linkSync(payload, destination)
        linked = true
      } catch (error) {
        if (isFsError(error, ['EEXIST'])) {
          fail(
            'DESTINATION_EXISTS',
            'Cannot restore: the destination was occupied while the restore was running. ' +
              'Nothing was moved and the item is still in the trash.',
          )
        }
        // `EPERM` (hard links restricted) and `EACCES` (sticky directory) are
        // permission failures, not "this filesystem has no hard links"; the
        // rename path below re-checks the destination, so they stay safe.
      }
      if (linked) {
        this.#dropPayload(payload, destination, mode)
        return
      }
    }

    if (existsAt(destination)) {
      fail(
        'DESTINATION_EXISTS',
        'Cannot restore: the destination was occupied while the restore was running. ' +
          'Nothing was moved and the item is still in the trash.',
      )
    }
    try {
      renameSync(payload, destination)
      return
    } catch (error) {
      if (!isFsError(error, ['EXDEV'])) throw error
    }
    placeByCopy(payload, destination)
  }

  /** Drop the archive copy after a hard link put the file back. */
  #dropPayload(payload, destination, mode) {
    // Windows refuses to unlink a read-only file. POSIX only needs write
    // permission on the containing directory, so do not chmod there: the
    // payload is hard-linked to the restored name and chmod would change its
    // mode.
    if (process.platform === 'win32') {
      try {
        chmodSync(payload, 0o600)
      } catch {
        // Not every filesystem exposes the attribute; the unlink decides.
      }
    }
    try {
      rmSync(payload, { force: true })
    } catch {
      // The restored name is already in place; a leftover archive copy is
      // removed with the item directory by the caller when that succeeds.
    } finally {
      if (process.platform === 'win32') {
        try {
          chmodSync(destination, mode)
        } catch {
          // The destination is already restored; preserve the original mode
          // where the filesystem supports it.
        }
      }
    }
  }

  /** Archive whatever currently occupies a restore destination. */
  #archiveOccupant(destination, sessionId = '') {
    const target = inspectTarget({ root: this.root, input: destination })
    this.ensureLayout()
    const id = newId()
    const itemDir = path.join(this.itemsRoot, id)
    let entries = 0
    if (target.kind === 'directory') {
      try {
        entries = readdirSync(target.absolute).length
      } catch (error) {
        wrapFsError('Cannot inspect the occupant directory', error, target.relative)
      }
    }
    const record = {
      version: 1,
      id,
      path: target.relative,
      kind: target.kind,
      entries,
      reason: 'restore overwrite',
      sessionId: typeof sessionId === 'string' ? sessionId.slice(0, 200) : '',
      deletedAt: new Date().toISOString(),
      status: 'pending',
    }
    try {
      mkdirSync(itemDir)
      writeMeta(itemDir, record)
    } catch (error) {
      wrapFsError('Cannot create the trash item', error, itemDir)
    }
    try {
      this.move(target.absolute, path.join(itemDir, 'payload'))
    } catch (error) {
      const sourceFailure = sourceRemovalFailure(error, `The occupant "${target.relative}"`, id)
      if (sourceFailure !== null) throw sourceFailure
      try {
        rmSync(itemDir, { recursive: true, force: true })
      } catch {
        // The move failed; cleanup is best effort and must not mask the cause.
      }
      wrapFsError('Cannot archive the existing occupant', error, target.relative)
    }
    try {
      writeMeta(itemDir, { ...record, status: 'trashed' })
    } catch {
      // Same as delete: the item is already complete on disk.
    }
    return id
  }

  /**
   * List recoverable items, newest first.
   * @param {{ query: string, trashId: string, limit: number, offset: number }} options
   */
  list({ query, trashId, limit, offset }) {
    // Reading the trash must not create or migrate anything: a read-only
    // session can list, and a parallel list must stay a pure read. A 1.x trash
    // is shown from its manifest and migrated by the next mutation.
    assertTrashRoot(this.root)
    const needle = typeof query === 'string' ? query.trim().toLowerCase() : ''
    const records = []
    let names
    try {
      names = readdirSync(this.itemsRoot, { withFileTypes: true })
    } catch (error) {
      if (isFsError(error, ['ENOENT'])) return { items: [], total: 0, trash_total: 0, offset: 0 }
      wrapFsError('Cannot read the trash directory', error, this.itemsRoot)
    }
    for (const entry of names) {
      if (entry.isSymbolicLink() || !entry.isDirectory() || !ID_RE.test(entry.name)) continue
      const itemDir = path.join(this.itemsRoot, entry.name)
      try {
        if (assertItemDirectory(this.itemsRoot, itemDir) === null) continue
      } catch {
        // A redirected or malformed item is not a recoverable trash entry.
        continue
      }
      let record = null
      try {
        record = readRecord(itemDir, entry.name)
        if (record === null) continue
        // A pending record whose payload landed is a completed deletion that was
        // interrupted before its final write; show it rather than hide the file.
        if (!existsAt(path.join(itemDir, 'payload'))) continue
      } catch {
        continue
      }
      records.push(record)
    }
    records.push(...this.#legacyRecords())
    records.sort((left, right) => {
      const leftAt = typeof left.deletedAt === 'string' ? left.deletedAt : String(left.deletedAt ?? '')
      const rightAt = typeof right.deletedAt === 'string' ? right.deletedAt : String(right.deletedAt ?? '')
      if (leftAt !== rightAt) return leftAt < rightAt ? 1 : -1
      return left.id < right.id ? 1 : left.id > right.id ? -1 : 0
    })

    const matches = records.filter((record) => {
      if (typeof trashId === 'string' && trashId !== '') return record.id === trashId
      if (needle === '') return true
      return `${record.id} ${record.path} ${record.reason} ${record.sessionId}`.toLowerCase().includes(needle)
    })
    const items = matches.slice(offset, offset + limit).map((record) => ({
      trash_id: record.id,
      path: record.path,
      kind: record.kind,
      entries: record.entries,
      deleted_at: record.deletedAt,
      reason: record.reason,
      session_id: record.sessionId,
    }))
    return { items, total: matches.length, trash_total: records.length, offset }
  }
}
