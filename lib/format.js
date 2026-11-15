// Model-facing text helpers.
//
// Tool results are the only place a path, reason or trash id becomes prompt
// text, so every one of them is flattened here: a filename with a newline must
// not be able to forge an extra result line.

/**
 * One line of untrusted text, at most `max` characters.
 * @param {unknown} value
 * @param {number} [max]
 */
export function formatText(value, max = 160) {
  if (typeof value !== 'string') return ''
  const flat = value
    // eslint-disable-next-line no-control-regex -- control characters are the point
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return flat.length > max ? `${flat.slice(0, Math.max(0, max - 1))}…` : flat
}

/** A workspace-relative path, or an id, for display. */
export function formatPath(value, max = 160) {
  return formatText(value, max)
}

/** An ISO timestamp for display; invalid values become an empty string. */
export function formatTime(value) {
  if (typeof value !== 'string') return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z')
}

/**
 * `3 entries` / `1 entry`, used in dry-run and list output.
 * @param {number} count
 */
export function formatEntries(count) {
  return `${count} ${count === 1 ? 'entry' : 'entries'}`
}
