'use client'

// Floating "who's online" panel (bottom-right, below the what-just-happened
// overlay). Reads the live roster the watch socket feeds into the presence
// store. Collapsed → "● N others online"; expanded → the list of online keys,
// plus your own row and a viewer tally. Locking drops you from the keyed members
// into the viewer count (and back on unlock) — so the panel makes lock/unlock
// visible to everyone in the repository, not just you.

import { useDockExpansion } from '../../lib/dock-expansion'
import { useIdentityStore } from '../../lib/identity-store'
import { usePresence } from '../../lib/presence-store'
import { PlayerLabel } from './player-label'

/** Compact "joined N ago" for a member's `since` (epoch ms). */
function ago(since: number): string {
  const m = Math.max(0, Math.round((Date.now() - since) / 60_000))
  return m < 1 ? 'just now' : `${m}m`
}

export function PresencePanel({ room }: { room: string }) {
  const { members, viewers } = usePresence(room)
  const myPubkey = useIdentityStore((s) => (s.unlocked ? s.ed25519PubkeyHex : null))
  // Expanded state is shared across the dock so only one panel is open at a time.
  const open = useDockExpansion((s) => s.expanded === 'presence')
  const openPanel = useDockExpansion((s) => s.open)
  const closePanel = useDockExpansion((s) => s.close)

  // Don't show anything until the socket reports a roster (SSR / pre-connect).
  if (members.length === 0 && viewers === 0) return null

  const iAmMember = !!myPubkey && members.some((m) => m.pubkeyHex === myPubkey)
  const others = members.filter((m) => m.pubkeyHex !== myPubkey)
  // When signed out, one of the viewers is me — don't count myself among "others".
  const otherViewers = Math.max(0, viewers - (iAmMember ? 0 : 1))
  // The "online" headline counts other identified members only — NOT yourself,
  // and NOT signed-out viewers (those are tallied separately below) so a lurker
  // can't inflate it.
  const onlineCount = others.length

  const summary =
    onlineCount > 0
      ? `${onlineCount} other${onlineCount === 1 ? '' : 's'} online`
      : otherViewers > 0
        ? `${otherViewers} viewing`
        : 'only you here'

  if (!open) {
    // Collapsed = an emoji circle in the dock row, with a small count badge.
    return (
      <button
        type='button'
        onClick={() => openPanel('presence')}
        title={summary}
        aria-label={`Who's online — ${summary}`}
        className='dock-pop-in relative inline-flex h-9 w-9 items-center justify-center rounded-full border border-hairline bg-bg text-base shadow-lg transition-colors hover:border-fg'
      >
        <span aria-hidden>👥</span>
        {onlineCount > 0 ? (
          <span className='absolute -top-1 -right-1 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-blue-600 px-1 text-[10px] font-semibold text-white'>
            {onlineCount}
          </span>
        ) : null}
      </button>
    )
  }

  return (
    <div className='dock-pop-in w-72 max-w-[calc(100vw-2rem)] overflow-hidden rounded-xl border border-hairline bg-bg text-sm shadow-xl'>
      <header className='flex items-center gap-2 border-b border-hairline px-3 py-2'>
        <span aria-hidden>👥</span>
        <span className='font-semibold'>Online · repo “{room}”</span>
        <button
          type='button'
          onClick={() => closePanel('presence')}
          aria-label='Collapse'
          className='ml-auto rounded-md px-1.5 py-0.5 text-xs text-muted transition-colors hover:bg-fg/10 hover:text-fg'
        >
          −
        </button>
      </header>

      <ul className='max-h-64 divide-y divide-dashed divide-hairline overflow-y-auto'>
        {/* You — a member when unlocked, otherwise a viewer. */}
        <li className='flex items-center gap-2 px-3 py-2'>
          <span aria-hidden className={`h-1.5 w-1.5 shrink-0 rounded-full ${myPubkey ? 'bg-green-500' : 'bg-muted'}`} />
          <span className='min-w-0 flex-1 truncate'>
            {myPubkey ? (
              <PlayerLabel pubkey={myPubkey} className='font-medium' />
            ) : (
              <span className='text-muted'>a viewer</span>
            )}
          </span>
          <span className='shrink-0 text-xs text-green-700 dark:text-green-400'>you{myPubkey ? '' : ' · viewer'}</span>
        </li>

        {others.map((m) => (
          <li key={m.pubkeyHex} className='flex items-center gap-2 px-3 py-2'>
            <span aria-hidden className='h-1.5 w-1.5 shrink-0 rounded-full bg-green-500' />
            <span className='min-w-0 flex-1 truncate'>
              <PlayerLabel pubkey={m.pubkeyHex} className='font-medium' />
            </span>
            <span className='shrink-0 font-mono text-[10px] text-muted'>{ago(m.since)}</span>
          </li>
        ))}

        {otherViewers > 0 ? (
          <li className='flex items-center gap-2 px-3 py-2 text-muted'>
            <span aria-hidden className='h-1.5 w-1.5 shrink-0 rounded-full bg-muted' />
            <span className='text-xs'>
              {otherViewers} signed-out viewer{otherViewers === 1 ? '' : 's'}
            </span>
          </li>
        ) : null}
      </ul>
    </div>
  )
}
