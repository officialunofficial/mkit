import { create } from 'zustand'

export type FileDraft = { path: string; content: string; original: string; hash: string | null; editable: boolean }
export function isDirtyDraft(draft: FileDraft): boolean {
  return draft.hash === null || draft.content !== draft.original
}
export const EMPTY_DRAFTS: Record<string, FileDraft> = Object.freeze(Object.create(null))
type DraftStore = {
  scopes: Map<string, Record<string, FileDraft>>
  setDraft: (scope: string, draft: FileDraft) => void
  discard: (scope: string, path?: string) => void
  clearAll: () => void
}

/** Private edits live only in memory, across route mounts but never across logins. */
export const useWorkspaceDraftStore = create<DraftStore>((set) => ({
  scopes: new Map(),
  setDraft: (scope, draft) =>
    set((state) => {
      const drafts = Object.assign(Object.create(null), state.scopes.get(scope))
      if (isDirtyDraft(draft)) drafts[draft.path] = draft
      else delete drafts[draft.path]
      const scopes = new Map(state.scopes)
      if (Object.keys(drafts).length) scopes.set(scope, drafts)
      else scopes.delete(scope)
      return { scopes }
    }),
  discard: (scope, path) =>
    set((state) => {
      const scopes = new Map(state.scopes)
      if (path === undefined) scopes.delete(scope)
      else {
        const drafts = Object.assign(Object.create(null), scopes.get(scope))
        delete drafts[path]
        if (Object.keys(drafts).length) scopes.set(scope, drafts)
        else scopes.delete(scope)
      }
      return { scopes }
    }),
  clearAll: () => set({ scopes: new Map() }),
}))
