// Shared constants + helpers for the multiplayer demo subcomponents.
// Moved verbatim out of `multiplayer-demo.tsx`.

export const BTN =
  'inline-flex h-10 shrink-0 items-center justify-center rounded-lg border border-hairline bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-blue-500/50 active:translate-y-px disabled:pointer-events-none disabled:opacity-50 sm:h-9'

// Primary call-to-action: filled blue with white text + a 1px offset dark-blue
// shadow, so the main action (create identity / sign & push) reads as clickable.
export const PRIMARY_BTN =
  'inline-flex h-10 shrink-0 items-center justify-center rounded-lg bg-blue-600 px-3 text-sm font-medium text-white shadow-[1px_1px_0_0_#1e3a8a] transition-all duration-200 hover:bg-blue-700 active:translate-y-px active:shadow-none disabled:pointer-events-none disabled:opacity-50 sm:h-9'

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message
  return String(e)
}
