// Shared constants + helpers for the multiplayer demo subcomponents.
// Moved verbatim out of `multiplayer-demo.tsx`.

// The two interaction accents, named once so inputs and ghost buttons stay in
// lockstep (and a soft-ring tweak is a one-line change, not a sweep):
//   HOVER_BORDER — the soft blue border a ghost button / interactive tile takes
//                  on hover (never a hard `border-fg`, which reads as a heavy
//                  black outline in light mode).
//   FOCUS_RING   — the soft focus treatment for a text input: a blue border plus
//                  a low-opacity blue halo. Already includes `outline-none` and
//                  the color transition; pair it with the element's own sizing.
export const HOVER_BORDER = 'hover:border-blue-500/50'
export const FOCUS_RING = 'outline-none transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-500/25'

export const BTN =
  'inline-flex h-10 shrink-0 items-center justify-center rounded-lg border border-hairline bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-blue-500/50 active:translate-y-px disabled:pointer-events-none disabled:opacity-50 sm:h-9'

// Primary call-to-action: filled blue with white text, so the main action
// (create identity / sign & push) reads as clickable.
export const PRIMARY_BTN =
  'inline-flex h-10 shrink-0 items-center justify-center rounded-lg bg-blue-600 px-3 text-sm font-medium text-white transition-all duration-200 hover:bg-blue-700 active:translate-y-px disabled:pointer-events-none disabled:opacity-50 sm:h-9'

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message
  return String(e)
}
