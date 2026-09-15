'use client'

import { Suspense, useState } from 'react'
import { UserCircleIcon, FingerprintIcon, XIcon, SignOutIcon, LockIcon, LockOpenIcon } from '@phosphor-icons/react/ssr'
import { useWorkspaceDraftStore } from '../lib/workspace-draft-store'
import { ModalLayer } from './top-layer'
import { useAuth } from './auth-provider'
import { ErrorBoundary } from './error-boundary'
import { UnlockedHeader } from './multiplayer/identity-panel'
import { OwnPlayerName, PlayerAvatar, PlayerLabel } from './multiplayer/player-label'
import { useMkit } from './use-mkit'

/** The shared account surface; login survives refresh, signing authority does not. */
export function Account() {
  const auth = useAuth()
  const [open, setOpen] = useState(false)
  const [confirmSignOut, setConfirmSignOut] = useState(false)
  const [proofOpen, setProofOpen] = useState(false)
  const publicKey = auth.session?.publicKey ?? ''
  const signingUnlocked = !!publicKey && auth.unlocked
  const state =
    auth.session === undefined ? (auth.pending ? 'loading' : 'error') : publicKey ? 'signed-in' : 'signed-out'
  const disabled = auth.busy || auth.pending

  return (
    <section
      aria-label='Account'
      data-auth-status={state}
      data-signing-status={signingUnlocked ? 'unlocked' : 'locked'}
      data-public-key={publicKey}
      className='text-sm'
    >
      <button
        type='button'
        aria-label={publicKey ? 'Account' : 'Sign in'}
        title={publicKey ? 'Account' : 'Sign in'}
        aria-haspopup='dialog'
        aria-expanded={open}
        onClick={() => setOpen(true)}
        className='touch-target inline-flex size-8 items-center justify-center rounded-(--rounded-sm) text-primary hover:bg-(--action-ghost-bg-hover)'
      >
        {publicKey ? <PlayerAvatar pubkey={publicKey} /> : <UserCircleIcon size={20} aria-hidden />}
      </button>
      {open ? (
        <ModalLayer label={publicKey ? 'Your account' : 'Sign in to mkit'} onClose={() => setOpen(false)}>
          <div className='mx-auto mt-24 w-[calc(100%-3rem)] max-w-md space-y-4 border border-hairline bg-page p-6'>
            <div className='flex items-center justify-between gap-4'>
              <h2 className='text-lg font-semibold'>{publicKey ? 'Your account' : 'Sign in to mkit'}</h2>
              <button
                type='button'
                aria-label='Close account'
                className='touch-target inline-flex size-8 items-center justify-center'
                onClick={() => setOpen(false)}
              >
                <XIcon size={18} aria-hidden />
              </button>
            </div>
            <div className='flex flex-wrap items-center gap-2'>
              {publicKey ? (
                <>
                  <div className='mr-auto flex min-w-0 flex-wrap items-center gap-2'>
                    <PlayerAvatar pubkey={publicKey} />
                    {signingUnlocked ? <OwnPlayerName /> : <PlayerLabel pubkey={publicKey} />}
                    <code title={publicKey} className='text-xs text-muted'>
                      {publicKey.slice(0, 10)}…
                    </code>
                    <span className='text-xs text-muted'>Signing {signingUnlocked ? 'unlocked' : 'locked'}</span>
                  </div>
                  {signingUnlocked ? (
                    <button
                      className='btn btn--outlined btn--small'
                      type='button'
                      disabled={disabled}
                      onClick={() => void auth.lockSigning()}
                    >
                      <LockIcon size={16} aria-hidden /> Lock signing
                    </button>
                  ) : (
                    <button
                      className='btn btn--solid btn--small'
                      type='button'
                      disabled={disabled}
                      onClick={() => void auth.onUnlock()}
                    >
                      <LockOpenIcon size={16} aria-hidden /> Unlock signing
                    </button>
                  )}
                  <button
                    className='btn btn--outlined btn--small'
                    type='button'
                    disabled={disabled}
                    onClick={() => {
                      if (useWorkspaceDraftStore.getState().scopes.size) setConfirmSignOut(true)
                      else void auth.signOut()
                    }}
                  >
                    <SignOutIcon size={16} aria-hidden /> Sign out
                  </button>
                  {signingUnlocked ? (
                    <button
                      className='btn btn--ghost btn--small'
                      type='button'
                      aria-expanded={proofOpen}
                      onClick={() => setProofOpen(!proofOpen)}
                    >
                      Passkey proof
                    </button>
                  ) : null}
                </>
              ) : state === 'loading' ? (
                <p role='status' className='text-muted'>
                  Checking your account…
                </p>
              ) : (
                <>
                  <p className='w-full text-muted'>
                    {state === 'error'
                      ? 'Account unavailable. Try again.'
                      : 'Use a passkey to access your projects. New to mkit? Create one to get started.'}
                  </p>
                  <button
                    className={`btn ${auth.hasPasskey ? 'btn--outlined' : 'btn--solid'} btn--small`}
                    type='button'
                    disabled={disabled}
                    onClick={() => void auth.onCreate()}
                  >
                    <FingerprintIcon size={16} aria-hidden /> Create a passkey
                  </button>
                  <button
                    className={`btn ${auth.hasPasskey ? 'btn--solid' : 'btn--outlined'} btn--small`}
                    type='button'
                    disabled={disabled}
                    onClick={() => void auth.onUnlock()}
                  >
                    <FingerprintIcon size={16} aria-hidden /> Use existing passkey
                  </button>
                </>
              )}
            </div>
            {confirmSignOut && publicKey ? (
              <ModalLayer label='Sign out and discard edits?' onClose={() => setConfirmSignOut(false)}>
                <div className='mx-auto mt-24 max-w-md space-y-4 border border-hairline bg-page p-6'>
                  <h2 className='text-lg font-semibold'>Sign out and discard edits?</h2>
                  <p>Unsaved edits in your workspaces will be discarded.</p>
                  <div className='flex justify-end gap-2'>
                    <button type='button' className='btn btn--outlined' onClick={() => setConfirmSignOut(false)}>
                      Keep editing
                    </button>
                    <button
                      type='button'
                      className='btn btn--solid'
                      disabled={disabled}
                      onClick={() => {
                        setConfirmSignOut(false)
                        void auth.signOut()
                      }}
                    >
                      Sign out and discard
                    </button>
                  </div>
                </div>
              </ModalLayer>
            ) : null}
            {auth.embeddedBrowserWarning ? <p className='text-xs text-muted'>{auth.embeddedBrowserWarning}</p> : null}
            {auth.status ? (
              <p role='status' className='text-xs text-muted'>
                {auth.status}
              </p>
            ) : null}
            {proofOpen && signingUnlocked ? (
              <ErrorBoundary>
                <Suspense fallback={<p className='text-xs text-muted'>Loading passkey proof…</p>}>
                  <PasskeyProof key={publicKey} publicKey={publicKey} />
                </Suspense>
              </ErrorBoundary>
            ) : null}
          </div>
        </ModalLayer>
      ) : null}
    </section>
  )
}

function PasskeyProof({ publicKey }: { publicKey: string }) {
  const api = useMkit()
  return <UnlockedHeader api={api} ed25519PubkeyHex={publicKey} proofOnly />
}
