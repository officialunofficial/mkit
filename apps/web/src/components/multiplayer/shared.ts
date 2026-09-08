// Shared constants + helpers for the multiplayer demo subcomponents.
// Moved verbatim out of `multiplayer-demo.tsx`.

// Shared Pigment hover, keyboard focus, and button styles.
export const HOVER_BORDER = 'hover:border-(--border-color-default)'
export const FOCUS_RING = 'transition-colors focus-visible:border-(--border-color-focus)'

export const BTN = 'btn btn--outlined shrink-0 justify-center font-medium'
export const PRIMARY_BTN = 'btn btn--solid shrink-0 justify-center font-medium'

// Every passkey / sign / push / chat error surfaces through `errMsg`, so this is
// the single place to keep raw browser strings (WebAuthn DOMExceptions, fetch
// failures) out of the UI. It delegates to the shared humanizer.
export { humanizeError as errMsg } from '../../lib/humanize-error'

// One wording per state, shared by the compose and repo-browser surfaces
// (style guide: same state, same words).
export const CAS_CONFLICT_COPY = 'Someone pushed first — try again.'
export const IDENTITY_LOCKED_COPY = 'Your identity is locked. Unlock it and try again.'
