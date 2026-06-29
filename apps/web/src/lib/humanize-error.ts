// Turn any thrown value — including raw WebAuthn / DOMExceptions and network
// failures — into ONE calm, blameless sentence with a next action. The user
// should never see a raw browser string: no spec URLs (e.g. the WebAuthn
// "The operation either timed out or was not allowed … w3.org/TR/webauthn"
// message), no fetch internals, no error codes.

const GENERIC = 'Something went wrong. Try again.'

// A passed-through message must read like human copy, not machinery. Reject the
// tells of a raw browser/network/thrown-internal string so they fall back to a
// calm generic line instead of leaking to the UI.
function looksTechnical(message: string): boolean {
  return (
    message.length > 140 ||
    /https?:\/\//i.test(message) || // spec URLs, endpoints
    /\b(fetch|networkerror|err_|econn|undefined|null|0x[0-9a-f]|\bat\s)\b/i.test(message) ||
    message.includes('\n')
  )
}

/**
 * Map a thrown value to user-facing copy. Matches on `.name` (stable across browsers) rather than `.message` (which
 * carries the localized spec text), then falls back to passing through a trusted Error message, then to a generic
 * line.
 */
export function humanizeError(e: unknown, fallback: string = GENERIC): string {
  const name = e instanceof DOMException ? e.name : (e as { name?: unknown })?.name
  const message = e instanceof Error ? e.message : ''

  switch (name) {
    case 'NotAllowedError': // the system passkey sheet was dismissed or timed out
    case 'TimeoutError':
      return 'Sign-in was canceled or timed out. Try again.'
    case 'AbortError':
      return 'Sign-in was canceled.'
    case 'InvalidStateError': // a passkey is already registered on this device
      return 'You already have a passkey on this device.'
    case 'SecurityError':
    case 'NotSupportedError':
      return "This browser can't use passkeys here."
  }

  // Some browsers throw the timeout/cancel as a plain Error, not a named
  // DOMException — catch it by its signature message too.
  if (/either timed out or was not allowed/i.test(message)) {
    return 'Sign-in was canceled or timed out. Try again.'
  }

  // A failed fetch surfaces as a TypeError with browser-specific wording.
  if (e instanceof TypeError) return "Couldn't reach the server. Check your connection and try again."

  // Our own thrown Errors now carry plain, mapped copy, so pass them through —
  // unless the message still reads like raw machinery.
  if (message && !looksTechnical(message)) return message
  return fallback
}
