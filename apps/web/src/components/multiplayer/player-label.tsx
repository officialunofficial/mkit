'use client'

// Display-name rendering for the multiplayer demo.
//
// A player's handle lives in the keys.mkit.sh registry (apps/keys-worker), keyed
// by Ed25519 pubkey. `useDisplayName` reads it (cached) and FALLS BACK to the
// deterministic `playerName(pubkey)` when the registry is disabled, has no entry,
// or errors — so names always render. `OwnPlayerName` adds an inline rename for
// the signed-in player (a signed write to the registry).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { playerName } from '../../lib/identity-name'
import { useIdentityStore } from '../../lib/identity-store'
import { getName, keysEnabled, setName } from '../../lib/keys-client'
import { PERSIST_MAX_AGE } from '../../lib/query-persist'
import { useMkit } from '../use-mkit'
import { BTN, errMsg } from './shared'

/** React Query key for a single player's registry handle. */
export function nameKey(pubkeyHex: string) {
  return ['keys', 'name', pubkeyHex] as const
}

/**
 * The display handle for a pubkey: the registry value if present, else the deterministic `playerName`. The query is
 * disabled (so always the fallback) when the registry isn't configured.
 */
export function useDisplayName(pubkeyHex: string | null): string {
  const q = useQuery({
    queryKey: nameKey(pubkeyHex ?? ''),
    queryFn: () => getName(pubkeyHex as string),
    enabled: keysEnabled() && !!pubkeyHex,
    staleTime: 60_000,
    // Keep cached handles long enough that the persisted cache (maxAge) can
    // rehydrate them — gcTime must be >= the persister's maxAge or they're
    // evicted before hydration surfaces them.
    gcTime: PERSIST_MAX_AGE,
  })
  if (!pubkeyHex) return 'anonymous'
  return q.data ?? playerName(pubkeyHex)
}

/** A pubkey's handle as a span. Used wherever a player is shown in the UI. */
export function PlayerLabel({ pubkey, className }: { pubkey: string; className?: string }) {
  const name = useDisplayName(pubkey)
  return <span className={className}>{name}</span>
}

/** Mutation: set/rename the signed-in player's own handle (signed write). */
export function useSetName() {
  const qc = useQueryClient()
  const api = useMkit()
  return useMutation({
    mutationFn: (a: { pubkeyHex: string; seedHex: string; name: string }) =>
      setName(api, a.seedHex, a.pubkeyHex, a.name),
    onSuccess: (name, a) => {
      // Reflect the new handle instantly, then reconcile with the registry.
      if (name) qc.setQueryData(nameKey(a.pubkeyHex), name)
      void qc.invalidateQueries({ queryKey: nameKey(a.pubkeyHex) })
    },
  })
}

/**
 * The signed-in player's own handle, with an inline rename. Editing is offered only when the registry is configured AND
 * the identity is recoverable (a non-ephemeral, unlocked passkey) — otherwise the name is display-only.
 */
export function OwnPlayerName() {
  const id = useIdentityStore()
  const pubkey = id.ed25519PubkeyHex ?? ''
  const current = useDisplayName(pubkey || null)
  const rename = useSetName()
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState('')

  const canEdit = keysEnabled() && !!id.seedHex && !!pubkey && !id.ephemeral

  const submit = () => {
    const name = value.trim()
    if (!name || !id.seedHex) return
    rename.mutate({ pubkeyHex: pubkey, seedHex: id.seedHex, name }, { onSuccess: () => setEditing(false) })
  }

  if (editing) {
    return (
      <span className='inline-flex flex-wrap items-center gap-2'>
        <input
          // biome-ignore lint/a11y/noAutofocus: focus the field the user just opened
          autoFocus
          className='w-32 rounded-md border border-hairline bg-transparent px-2 py-1 text-sm outline-none focus:border-fg sm:w-40'
          value={value}
          maxLength={32}
          placeholder={current}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') submit()
            if (e.key === 'Escape') setEditing(false)
          }}
        />
        <button type='button' className={BTN} onClick={submit} disabled={rename.isPending}>
          {rename.isPending ? 'Saving…' : 'Save'}
        </button>
        <button type='button' className={BTN} onClick={() => setEditing(false)} disabled={rename.isPending}>
          Cancel
        </button>
        {rename.isError ? (
          <span className='text-xs text-amber-700 dark:text-amber-400'>{errMsg(rename.error)}</span>
        ) : null}
      </span>
    )
  }

  return (
    <span className='inline-flex items-center gap-2'>
      <span className='font-medium'>{current}</span>
      {canEdit ? (
        <button
          type='button'
          className='text-xs text-muted underline-offset-2 hover:text-fg hover:underline'
          onClick={() => {
            setValue(current)
            setEditing(true)
          }}
        >
          rename
        </button>
      ) : null}
    </span>
  )
}
