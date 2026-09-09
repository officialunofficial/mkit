'use client'
import { useCallback, useId } from 'react'
import { EMPTY_DRAFTS, useWorkspaceDraftStore, type FileDraft } from '../../lib/workspace-draft-store'
export { isDirtyDraft, type FileDraft } from '../../lib/workspace-draft-store'

/** Session + identity + workspace scope preserves edits when a route is remounted. */
export function useWorkspaceDrafts(scope?: string) {
  const instance = useId()
  const key = scope ?? instance
  const drafts = useWorkspaceDraftStore((state) => state.scopes.get(key) ?? EMPTY_DRAFTS)
  const setDraft = useCallback((draft: FileDraft) => useWorkspaceDraftStore.getState().setDraft(key, draft), [key])
  const discard = useCallback((path?: string) => useWorkspaceDraftStore.getState().discard(key, path), [key])
  const clear = useCallback(() => useWorkspaceDraftStore.getState().discard(key), [key])
  return { drafts, setDraft, discard, clear, dirty: Object.keys(drafts).length > 0 }
}
export type WorkspaceDraftState = ReturnType<typeof useWorkspaceDrafts>
