// One error type for every refusal and failure the plugin raises.
//
// The `code` is the stable part: tool results, tests and logs key on it instead
// of matching prose. Messages are written for the model and must say what was
// refused and what to do next, because the message is all a tool failure shows.

/** A refusal or failure raised by the plugin itself (not an OS error). */
export class SafeDeleteError extends Error {
  /**
   * @param {string} code - stable machine-readable code.
   * @param {string} message - model-facing explanation and next step.
   * @param {{ cause?: unknown }} [options] - the underlying failure, when any.
   */
  constructor(code, message, options = {}) {
    super(`[${code}] ${message}`, options)
    this.name = 'SafeDeleteError'
    this.code = code
  }
}

/**
 * Throw one {@link SafeDeleteError}.
 * @param {string} code
 * @param {string} message
 * @param {{ cause?: unknown }} [options]
 * @returns {never}
 */
export function fail(code, message, options) {
  throw new SafeDeleteError(code, message, options)
}

/**
 * Is this an expected filesystem error rather than a plugin bug?
 * @param {unknown} error
 * @param {readonly string[]} codes
 */
export function isFsError(error, codes) {
  return Boolean(error) && typeof error === 'object' && codes.includes(/** @type {any} */ (error).code)
}
