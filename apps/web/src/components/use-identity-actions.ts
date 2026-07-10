'use client'

// The passkey identity ceremony as a reusable hook — create (one-shot
// PRF-on-create, falling back to a get() or an ephemeral key) and unlock
// (recover the SAME Ed25519 key from the existing passkey via PRF). Shared by
// the multiplayer demo and the front-page signed lobby so the ceremony (and its
// keys.mkit.sh handle registration) lives in ONE place; both write the same
// global identity store, so unlocking in either surface unlocks the other.

import { useState } from 'react'
import { recordActivity } from '../lib/activity-log'
import { embeddedBrowserWarning } from '../lib/embedded-browser'
import { playerName, randomPetname } from '../lib/identity-name'
import { useIdentityStore } from '../lib/identity-store'
import { keysEnabled } from '../lib/keys-client'
import { PrfUnsupportedError, createIdentity, deriveEd25519Seed } from '../lib/passkey'
import { errMsg } from './multiplayer/shared'
import { useSetName } from './multiplayer/player-label'
import { bytesToHex, hexToBytes, useMkit } from './use-mkit'

export type IdentityActions = {
  onCreate: () => Promise<void>
  onUnlock: () => Promise<void>
  busy: boolean
  status: string | null
  setStatus: (s: string | null) => void
  /** True when a recoverable passkey is on file (drives Create vs Unlock). */
  hasPasskey: boolean
  unlocked: boolean
  /** Proactive "open this in your browser" notice, or null — see lib/embedded-browser.ts. */
  embeddedBrowserWarning: string | null
}

export function useIdentityActions(): IdentityActions {
  const api = useMkit()
  const id = useIdentityStore()
  const setNameMut = useSetName()
  const [status, setStatus] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // The UA doesn't change mid-session, so compute lazily once rather than on every render.
  const [warning] = useState(embeddedBrowserWarning)

  // One ceremony: create the passkey AND derive the Ed25519 seed (PRF-on-create),
  // falling back to one get() or an ephemeral key inside `createIdentity`. Every
  // signed write afterwards uses the in-memory key — no further prompts.
  const onCreate = async () => {
    setStatus(null)
    setBusy(true)
    try {
      // Roll a friendly handle BEFORE creation so the passkey is saved as
      // "slate-badger@<host>" (not "mkit player@<host>") in the OS passkey
      // manager. The same handle is registered to the derived pubkey below so it
      // survives recovery and is what other players see.
      const petname = randomPetname()
      // Record the chosen handle locally so the app shows the SAME name the OS
      // passkey manager does — even without a keys.mkit.sh registry (where it
      // would otherwise be lost and the UI would fall back to a DIFFERENT,
      // pubkey-derived `playerName`).
      id.setName(petname)
      const res = await createIdentity(petname)
      // Persist the credentialId ONLY for a real (passkey-backed) identity. The
      // ephemeral fallback returns a credentialId too, but its seed is RANDOM —
      // not derived from that passkey — so persisting it would flip `hasPasskey`
      // true and surface an "Unlock" that derives a DIFFERENT seed.
      if (res.credentialId && res.via !== 'ephemeral') {
        id.setCredentialId(res.credentialId)
        // Populate the attestation pubkey alongside the credential — null on
        // legacy/exotic authenticators just disables the "Link with a
        // passkey" button, it never blocks identity creation.
        id.setP256PubkeyHex(res.p256PubkeyHex)
      }
      // Time ONLY the local key-derivation compute (seed → Ed25519 pubkey) — NOT
      // the passkey ceremony, which is user/OS-gated and would misrepresent the
      // "fast" story. This is the genuinely sub-ms part worth flexing.
      const t0 = performance.now()
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(res.seedHex)))
      const deriveMs = performance.now() - t0
      id.unlock({ seedHex: res.seedHex, ed25519PubkeyHex: pubkey, ephemeral: res.via === 'ephemeral' })
      // Register the handle in keys.mkit.sh (signed write). Fire-and-forget and
      // only for a recoverable identity with a configured registry.
      if (res.via !== 'ephemeral' && keysEnabled()) {
        setNameMut.mutate({ pubkeyHex: pubkey, seedHex: res.seedHex, name: petname })
      }
      setStatus(
        res.via === 'ephemeral'
          ? "Your device can't save this identity, so it'll only last until you close this tab."
          : 'Your identity is ready.',
      )
      recordActivity({
        kind: 'create',
        title: `New player: ${petname}`,
        durationMs: deriveMs,
        lines: [
          res.via === 'ephemeral'
            ? 'No passkey PRF here, so this is a random in-memory key — it won’t persist or recover.'
            : 'Your passkey derived a 32-byte Ed25519 seed in a single prompt — no key file, nothing stored to disk.',
          `Signer pubkey ${pubkey.slice(0, 12)}… (renders as ${petname}).`,
          'The seed stays in memory only, and the same passkey always re-derives it: same passkey, same player, any device.',
        ],
      })
    } catch (e) {
      setStatus(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  // RECOVER the SAME identity (after a Lock, or on a returning visit). Unlike
  // `onCreate`, this does NOT mint a new passkey: `deriveEd25519Seed` runs a
  // get() that re-derives the SAME PRF → SAME seed → SAME Ed25519 pubkey from
  // the existing (resident) passkey.
  const onUnlock = async () => {
    setStatus(null)
    setBusy(true)
    try {
      const res = await deriveEd25519Seed(id.credentialId ?? undefined)
      if (res.credentialId) id.setCredentialId(res.credentialId)
      // NOTE: we deliberately do NOT (and CANNOT) set `p256PubkeyHex` here. The
      // credential's own P-256 public key is exposed only by
      // `AuthenticatorAttestationResponse.getPublicKey()` — a CREATION-time API.
      // A `get()` assertion (this unlock/recovery path) never carries it. So a
      // cross-device recovery or any pre-#494 identity keeps `p256PubkeyHex`
      // null, which just disables the optional "Link with a passkey" attest
      // button (see identity-panel `canAttest`) — the signing identity itself is
      // fully usable. There is no non-destructive way to re-capture it: minting a
      // new passkey would derive a DIFFERENT seed, i.e. a different player.
      const t0 = performance.now()
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(res.seedHex)))
      const deriveMs = performance.now() - t0
      id.unlock({ seedHex: res.seedHex, ed25519PubkeyHex: pubkey, ephemeral: false })
      setStatus('Your identity is unlocked.')
      recordActivity({
        kind: 'unlock',
        title: `Recovered ${playerName(pubkey)} — same key, no key file`,
        durationMs: deriveMs,
        lines: [
          'The same passkey re-derived the same seed, so you get the same Ed25519 key — no new passkey created.',
          `Signer pubkey ${pubkey.slice(0, 12)}… — identical to before, because it’s derived, not stored.`,
        ],
      })
    } catch (e) {
      if (e instanceof PrfUnsupportedError) {
        setStatus("This passkey can't unlock your signing key. Create a new identity instead.")
      } else {
        setStatus(errMsg(e))
      }
    } finally {
      setBusy(false)
    }
  }

  return {
    onCreate,
    onUnlock,
    busy,
    status,
    setStatus,
    hasPasskey: id.credentialId != null,
    unlocked: id.unlocked,
    embeddedBrowserWarning: warning,
  }
}
