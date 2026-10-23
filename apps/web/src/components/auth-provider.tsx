'use client'

import { useMutation } from '@tanstack/react-query'
import { createContext, useContext, useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { embeddedBrowserWarning } from '../lib/embedded-browser'
import { randomPetname } from '../lib/identity-name'
import { useIdentityStore, type IdentityState } from '../lib/identity-store'
import { keysEnabled } from '../lib/keys-client'
import { mkit } from '../lib/mkit'
import { createIdentity, deriveEd25519Seed } from '../lib/passkey'
import { useSetName } from './multiplayer/player-label'
import { errMsg } from './multiplayer/shared'
import { bytesToHex, hexToBytes } from './use-mkit'

export const AUTH_CHANGE_KEY = 'mkit-auth-change'
type Auth = {
  /** Hex Ed25519 public key of the remembered identity, or null when signed out. Null until the client has mounted. */
  publicKey: string | null
  pending: boolean
  busy: boolean
  status: string | null
  setStatus: (status: string | null) => void
  hasPasskey: boolean
  unlocked: boolean
  embeddedBrowserWarning: string | null
  onCreate: () => Promise<void>
  onUnlock: () => Promise<void>
  signOut: () => Promise<void>
  lockSigning: () => Promise<void>
  ensureSigning: (expectedPublicKey?: string) => Promise<IdentityState>
  epoch: () => number
}
const AuthContext = createContext<Auth | null>(null)
const subscribeClient = () => () => {}
const isClient = () => true
const isServer = () => false

function broadcast(action: 'login' | 'logout' | 'lock') {
  try {
    localStorage.setItem(AUTH_CHANGE_KEY, JSON.stringify({ action, nonce: crypto.randomUUID() }))
  } catch {
    /* Storage may be disabled. */
  }
}

/** One passkey ceremony and one identity observer for the entire application; identity lives only in this browser. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const identity = useIdentityStore()
  const names = useSetName()
  const generation = useRef(0)
  const flight = useRef<Promise<void> | null>(null)
  const ready = useSyncExternalStore(subscribeClient, isClient, isServer)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState<string | null>(null)
  const [warning] = useState(embeddedBrowserWarning)
  const publicKey = ready ? identity.knownPublicKey : null
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== AUTH_CHANGE_KEY || !event.newValue) return
      let action: unknown
      try {
        action = JSON.parse(event.newValue).action
      } catch {
        return
      }
      if (!['login', 'logout', 'lock'].includes(String(action))) return
      generation.current++
      // Read the new tab's public metadata before lock() persists our slice.
      void useIdentityStore.persist?.rehydrate()
      useIdentityStore.getState().lock()
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const ceremony = useMutation({
    mutationKey: ['auth', 'ceremony'],
    // Only an intent enters the mutation cache; signing material stays in memory.
    mutationFn: async (mode: 'create' | 'unlock'): Promise<void> => {
      const epoch = generation.current
      const current = useIdentityStore.getState()
      const prior = current.knownPublicKey
      if (mode === 'create' && prior) throw new Error('Sign out before creating another identity.')
      const petname = mode === 'create' ? randomPetname() : null
      const result =
        mode === 'create' ? await createIdentity(petname!) : await deriveEd25519Seed(current.credentialId ?? undefined)
      if ('via' in result && result.via === 'ephemeral')
        throw new Error('This device cannot save a signing identity. Use a browser with passkey PRF support.')
      const api = await mkit()
      const derived = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(result.seedHex)))
      if (prior && derived !== prior)
        throw new Error('That passkey belongs to another identity. Sign out to switch accounts.')
      if (epoch !== generation.current) throw new Error('Your sign-in changed during this request. Try again.')
      const credentialId = result.credentialId ?? current.credentialId
      if (!credentialId) throw new Error('A saved passkey is required.')
      if (current.credentialId !== credentialId) {
        current.setP256PubkeyHex(null)
        current.setName(null)
      }
      current.setCredentialId(credentialId)
      if ('p256PubkeyHex' in result)
        current.setP256PubkeyHex(typeof result.p256PubkeyHex === 'string' ? result.p256PubkeyHex : null)
      if (petname) current.setName(petname)
      current.unlock({ seedHex: result.seedHex, ed25519PubkeyHex: derived, ephemeral: false })
      if (petname && keysEnabled()) names.mutate({ pubkeyHex: derived, name: petname })
      setStatus(null)
      if (!prior) broadcast('login')
    },
    gcTime: 0,
    retry: false,
  })
  function runCeremony(mode: 'create' | 'unlock'): Promise<void> {
    if (flight.current) return flight.current
    setStatus(null)
    setBusy(true)
    const promise = ceremony.mutateAsync(mode).finally(() => {
      if (flight.current === promise) flight.current = null
      setBusy(false)
    })
    flight.current = promise
    return promise
  }
  async function reportCeremony(mode: 'create' | 'unlock') {
    try {
      await runCeremony(mode)
    } catch (error) {
      setStatus(errMsg(error))
    }
  }
  async function ensureSigning(expectedPublicKey?: string) {
    const active = useIdentityStore.getState().knownPublicKey
    if (!active) throw new Error('Sign in to make changes.')
    if (expectedPublicKey && active !== expectedPublicKey)
      throw new Error('This workspace belongs to another identity.')
    let key = useIdentityStore.getState()
    if (!key.unlocked || !key.seedHex || key.ed25519PubkeyHex !== active) {
      await runCeremony('unlock')
      key = useIdentityStore.getState()
    }
    if (!key.unlocked || !key.seedHex || key.ed25519PubkeyHex !== active)
      throw new Error('Signing identity changed. Try again.')
    return key
  }
  async function lockSigning() {
    generation.current++
    useIdentityStore.getState().lock()
    setStatus(null)
    broadcast('lock')
  }
  async function signOut() {
    // Bumping the generation makes an in-flight ceremony fail instead of unlocking after sign-out.
    generation.current++
    useIdentityStore.getState().signOut()
    setStatus(null)
    broadcast('logout')
  }
  return (
    <AuthContext.Provider
      value={{
        publicKey,
        pending: !ready,
        busy,
        status,
        setStatus,
        hasPasskey: !!identity.credentialId,
        unlocked: identity.unlocked,
        embeddedBrowserWarning: warning,
        onCreate: () => reportCeremony('create'),
        onUnlock: () => reportCeremony('unlock'),
        signOut,
        lockSigning,
        ensureSigning,
        epoch: () => generation.current,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): Auth {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth requires AuthProvider')
  return value
}
