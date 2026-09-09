'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react'
import { embeddedBrowserWarning } from '../lib/embedded-browser'
import { randomPetname } from '../lib/identity-name'
import { useIdentityStore, type IdentityState } from '../lib/identity-store'
import { keysEnabled } from '../lib/keys-client'
import { mkit } from '../lib/mkit'
import { createIdentity, deriveEd25519Seed } from '../lib/passkey'
import { WORKSPACE_API, workspaceRead, workspaceWrite } from '../lib/workspace-client'
import { useWorkspaceDraftStore } from '../lib/workspace-draft-store'
import { useSetName } from './multiplayer/player-label'
import { errMsg } from './multiplayer/shared'
import { bytesToHex, hexToBytes } from './use-mkit'

export type BrowserSession = { id: string; publicKey: string; expiresAt: number }
export const SESSION_KEY = ['auth', 'session'] as const
export const AUTH_CHANGE_KEY = 'mkit-auth-change'
type Auth = {
  session: BrowserSession | null | undefined
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

/** One server session observer and one passkey ceremony for the entire application. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const identity = useIdentityStore()
  const names = useSetName()
  const generation = useRef(0)
  const flight = useRef<Promise<void> | null>(null)
  const loggingOut = useRef(false)
  const ready = useSyncExternalStore(subscribeClient, isClient, isServer)
  const [signingOut, setSigningOut] = useState(false)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState<string | null>(null)
  const [warning] = useState(embeddedBrowserWarning)
  const sessionQuery = useQuery({
    queryKey: SESSION_KEY,
    queryFn: ({ signal }) => workspaceRead<BrowserSession | null>('/session', signal),
    enabled: ready && !signingOut,
    staleTime: 60_000,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    refetchInterval: 60_000,
    retry: false,
  })
  useEffect(() => {
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!useWorkspaceDraftStore.getState().scopes.size) return
      event.preventDefault()
      event.returnValue = ''
    }
    window.addEventListener('beforeunload', beforeUnload)
    return () => window.removeEventListener('beforeunload', beforeUnload)
  }, [])
  const observedSession = useRef<BrowserSession | null | undefined>(undefined)
  const session = sessionQuery.data
  const clearPrivate = useCallback(() => {
    useWorkspaceDraftStore.getState().clearAll()
    void qc.cancelQueries({ queryKey: ['workspaces'] })
    qc.removeQueries({ queryKey: ['workspaces'] })
    for (const mutation of qc.getMutationCache().getAll()) {
      if (mutation.options.mutationKey?.[0] === 'workspaces') qc.getMutationCache().remove(mutation)
    }
  }, [qc])
  function broadcast(action: 'session' | 'logout' | 'lock') {
    try {
      localStorage.setItem(AUTH_CHANGE_KEY, JSON.stringify({ action, nonce: crypto.randomUUID() }))
    } catch {
      /* Storage may be disabled. */
    }
  }
  const deleteSession = useCallback(async () => {
    const response = await fetch(`${WORKSPACE_API}/session`, { method: 'DELETE', credentials: 'same-origin' })
    if (!response.ok) throw new Error('Sign out failed. Try again to close your server session.')
    clearPrivate()
    qc.setQueryData(SESSION_KEY, null)
  }, [qc, clearPrivate])
  useEffect(() => {
    const previous = observedSession.current
    if (previous && session && (previous.id !== session.id || previous.publicKey !== session.publicKey)) {
      generation.current++
      clearPrivate()
    }
    if (session !== undefined) observedSession.current = session
    if (session === null || (session && identity.ed25519PubkeyHex !== session.publicKey)) {
      useIdentityStore.getState().lock()
      if (session === null) {
        generation.current++
        clearPrivate()
      }
    }
  }, [session, identity.ed25519PubkeyHex, clearPrivate])
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== AUTH_CHANGE_KEY || !event.newValue) return
      let action: unknown
      try {
        action = JSON.parse(event.newValue).action
      } catch {
        return
      }
      if (!['session', 'logout', 'lock'].includes(String(action))) return
      generation.current++
      // Read the new tab's public metadata before lock() persists our slice.
      void useIdentityStore.persist?.rehydrate()
      useIdentityStore.getState().lock()
      if (action === 'lock') return
      clearPrivate()
      void qc.cancelQueries({ queryKey: SESSION_KEY })
      if (action === 'logout') {
        qc.setQueryData(SESSION_KEY, null)
        // An already-running login can finish after another tab signs out.
        // Revoke its cookie once that request settles.
        const pending = flight.current
        if (pending)
          void pending
            .catch(() => {})
            .then(deleteSession)
            .catch((error) => setStatus(errMsg(error)))
      } else void qc.resetQueries({ queryKey: SESSION_KEY })
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [qc, clearPrivate, deleteSession])

  const ceremony = useMutation({
    mutationKey: ['auth', 'ceremony'],
    // Only an intent enters the mutation cache; signing material stays in memory.
    mutationFn: async (mode: 'create' | 'unlock'): Promise<void> => {
      const epoch = generation.current
      const prior = qc.getQueryData<BrowserSession | null>(SESSION_KEY)
      const current = useIdentityStore.getState()
      if (mode === 'create' && prior) throw new Error('Sign out before creating another identity.')
      const petname = mode === 'create' ? randomPetname() : null
      const credential =
        prior && current.knownPublicKey !== prior.publicKey ? undefined : (current.credentialId ?? undefined)
      const result = mode === 'create' ? await createIdentity(petname!) : await deriveEd25519Seed(credential)
      if ('via' in result && result.via === 'ephemeral')
        throw new Error('This device cannot save a signing identity. Use a browser with passkey PRF support.')
      const api = await mkit()
      const publicKey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(result.seedHex)))
      if (prior && publicKey !== prior.publicKey)
        throw new Error('That passkey belongs to another identity. Sign out to switch accounts.')
      if (epoch !== generation.current) throw new Error('Authentication changed. Please try again.')
      const candidate: IdentityState = {
        ...current,
        credentialId: result.credentialId ?? current.credentialId,
        seedHex: result.seedHex,
        ed25519PubkeyHex: publicKey,
        unlocked: true,
        ephemeral: false,
      }
      if (!candidate.credentialId) throw new Error('A saved passkey is required.')
      // Cancelling the observer prevents an earlier anonymous GET overwriting this login.
      await qc.cancelQueries({ queryKey: SESSION_KEY })
      const next = prior ?? (await workspaceWrite<BrowserSession>(api, candidate, 'identity', '/session', {}))
      if (epoch !== generation.current) throw new Error('Authentication changed. Please try again.')
      if (next.publicKey !== publicKey) throw new Error('Server session identity did not match.')
      if (!prior) clearPrivate()
      if (current.credentialId !== candidate.credentialId) {
        current.setP256PubkeyHex(null)
        current.setName(null)
      }
      current.setCredentialId(candidate.credentialId)
      if ('p256PubkeyHex' in result)
        current.setP256PubkeyHex(typeof result.p256PubkeyHex === 'string' ? result.p256PubkeyHex : null)
      if (petname) current.setName(petname)
      qc.setQueryData(SESSION_KEY, next)
      current.unlock({ seedHex: result.seedHex, ed25519PubkeyHex: publicKey, ephemeral: false })
      if (petname && keysEnabled()) names.mutate({ pubkeyHex: publicKey, name: petname })
      setStatus(null)
      if (!prior) broadcast('session')
    },
    gcTime: 0,
    retry: false,
  })
  function runCeremony(mode: 'create' | 'unlock'): Promise<void> {
    if (loggingOut.current) return Promise.reject(new Error('Sign out is still finishing.'))
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
    const active = qc.getQueryData<BrowserSession | null>(SESSION_KEY)
    if (!active || loggingOut.current) throw new Error('Sign in to make changes.')
    if (expectedPublicKey && active.publicKey !== expectedPublicKey)
      throw new Error('This workspace belongs to another identity.')
    let key = useIdentityStore.getState()
    if (!key.unlocked || !key.seedHex || key.ed25519PubkeyHex !== active.publicKey) {
      await runCeremony('unlock')
      key = useIdentityStore.getState()
    }
    if (!key.unlocked || !key.seedHex || key.ed25519PubkeyHex !== active.publicKey || loggingOut.current)
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
    if (loggingOut.current) return
    const previousSession = qc.getQueryData<BrowserSession | null>(SESSION_KEY)
    loggingOut.current = true
    setSigningOut(true)
    generation.current++
    setBusy(true)
    useIdentityStore.getState().lock()
    clearPrivate()
    await qc.cancelQueries({ queryKey: SESSION_KEY })
    qc.setQueryData(SESSION_KEY, null)
    try {
      await flight.current?.catch(() => {})
      await deleteSession()
      setStatus(null)
      broadcast('logout')
    } catch (error) {
      qc.setQueryData(SESSION_KEY, previousSession)
      setStatus(errMsg(error))
    } finally {
      loggingOut.current = false
      setSigningOut(false)
      setBusy(false)
    }
  }
  return (
    <AuthContext.Provider
      value={{
        session: signingOut ? undefined : session,
        pending: signingOut || sessionQuery.isPending,
        busy: busy || signingOut,
        status: status ?? (sessionQuery.isError ? 'Could not check your session. Reconnect and try again.' : null),
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
