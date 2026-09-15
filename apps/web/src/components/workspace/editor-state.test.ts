// @vitest-environment jsdom
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { useWorkspaceDrafts } from './editor-state'
afterEach(cleanup)
it('retains special file names as ordinary drafts and can discard one without losing others', () => {
  const { result } = renderHook(useWorkspaceDrafts)
  expect(result.current.drafts.constructor).toBeUndefined()
  act(() => {
    for (const path of ['constructor', '__proto__'])
      result.current.setDraft({ path, content: '', original: '', hash: null, editable: true })
  })
  expect(Object.keys(result.current.drafts)).toEqual(['constructor', '__proto__'])
  expect(result.current.dirty).toBe(true)
  act(() => result.current.discard('constructor'))
  expect(Object.keys(result.current.drafts)).toEqual(['__proto__'])
  act(() => result.current.clear())
  expect(result.current.dirty).toBe(false)
  expect(result.current.drafts.constructor).toBeUndefined()
})
it('removes an existing file draft when its content returns to its original value', () => {
  const { result } = renderHook(useWorkspaceDrafts)
  const original = { path: 'README.md', content: 'original', original: 'original', hash: 'hash', editable: true }
  act(() => result.current.setDraft({ ...original, content: 'edited' }))
  expect(result.current.dirty).toBe(true)
  act(() => result.current.setDraft(original))
  expect(result.current.dirty).toBe(false)
  expect(Object.keys(result.current.drafts)).toEqual([])
})

it('retains drafts across route unmounts and isolates session and workspace scopes', () => {
  const first = renderHook(() => useWorkspaceDrafts('session-a:workspace-a'))
  act(() =>
    first.result.current.setDraft({ path: '__proto__', content: 'edit', original: '', hash: null, editable: true }),
  )
  first.unmount()
  const same = renderHook(() => useWorkspaceDrafts('session-a:workspace-a'))
  const otherWorkspace = renderHook(() => useWorkspaceDrafts('session-a:workspace-b'))
  const otherSession = renderHook(() => useWorkspaceDrafts('session-b:workspace-a'))
  expect(same.result.current.drafts.__proto__?.content).toBe('edit')
  expect(otherWorkspace.result.current.dirty).toBe(false)
  expect(otherSession.result.current.dirty).toBe(false)
  act(() => same.result.current.clear())
})
