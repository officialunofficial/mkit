import {
  WORKSPACE_API,
  grantMessage,
  type PreparedWorkspace,
  type RemixRequest,
  type WorkspaceView,
} from '../../../workspace-worker/src/contracts'
import { useIdentityStore, type IdentityState } from './identity-store'
import type { MkitApi } from './mkit'
import { buildSignedEnvelope, envelopeHeaders } from './repo/envelope'
import { bytesToHex, hexToBytes } from '../components/use-mkit'
export { WORKSPACE_API }
export type * from '../../../workspace-worker/src/contracts'

export function hasWorkspaceIdentity(
  id: Pick<IdentityState, 'unlocked' | 'ephemeral' | 'credentialId' | 'seedHex'>,
): boolean {
  return id.unlocked && !id.ephemeral && !!id.credentialId && !!id.seedHex
}

export async function workspaceRead<T>(path = '', signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${WORKSPACE_API}${path}`, { credentials: 'same-origin', ...(signal ? { signal } : {}) })
  return readResponse<T>(response)
}

async function readResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const data = await response.json().catch(() => null)
    throw new Error(data?.error || `Workspace request failed (${response.status}). Try again.`)
  }
  return response.json()
}

export async function workspaceWrite<T>(
  api: MkitApi,
  id: IdentityState,
  repository: string,
  action: string,
  value: unknown,
): Promise<T> {
  if (!hasWorkspaceIdentity(id) || !id.seedHex) throw new Error('Unlock a saved passkey identity to make changes.')
  const body = JSON.stringify(value)
  const procedure = `${WORKSPACE_API}${action}`
  const envelope = buildSignedEnvelope(api, id.seedHex, {
    audience: location.origin,
    repository,
    procedure,
    bodyDigest: api.blake3_hex(new TextEncoder().encode(body)),
  })
  const response = await fetch(procedure, {
    method: 'POST',
    credentials: 'same-origin',
    body,
    headers: { 'Content-Type': 'application/json', ...envelopeHeaders(envelope) },
  })
  return readResponse<T>(response)
}

export async function remixWorkspace(
  api: MkitApi,
  identity: IdentityState,
  source: RemixRequest,
): Promise<WorkspaceView> {
  const prepared = await workspaceWrite<PreparedWorkspace>(api, identity, 'workspaces', '/prepare', source)
  // Preparation is asynchronous. Do not retain signing authority after the user locks or switches identity.
  const currentIdentity = useIdentityStore.getState()
  if (!hasWorkspaceIdentity(currentIdentity) || currentIdentity.seedHex !== identity.seedHex)
    throw new Error('Identity changed. Unlock your passkey and remix again.')
  if (!hasWorkspaceIdentity(identity) || !identity.seedHex) throw new Error('Unlock your passkey identity.')
  if (prepared.grant.ownerPublicKey !== identity.ed25519PubkeyHex || prepared.grant.workspaceId !== prepared.id)
    throw new Error('Workspace identity did not match. Please try again.')
  const signature = bytesToHex(
    api.ed25519_sign(
      hexToBytes(api.blake3_hex(new TextEncoder().encode(grantMessage(prepared.grant)))),
      hexToBytes(identity.seedHex),
    ),
  )
  return workspaceWrite(api, currentIdentity, prepared.id, `/${prepared.id}/activate`, {
    grant: prepared.grant,
    signature,
  })
}
