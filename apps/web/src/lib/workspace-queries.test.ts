import { expect, it } from 'vitest'
import { workspaceKeys } from './workspace-queries'
it('keys current files by content hash but keeps historical file keys independent of current work', () => {
  const session = { id: 'session', publicKey: 'owner' }
  expect(workspaceKeys.file('workspace', session, 'README.md', null, 'first')).not.toEqual(
    workspaceKeys.file('workspace', session, 'README.md', null, 'second'),
  )
  expect(workspaceKeys.file('workspace', session, 'README.md', 'saved-version', 'first')).toEqual(
    workspaceKeys.file('workspace', session, 'README.md', 'saved-version', 'second'),
  )
  expect(workspaceKeys.file('workspace', session, 'README.md', 'saved-version', 'first')).not.toEqual(
    workspaceKeys.file('workspace', session, 'README.md', 'other-version', 'first'),
  )
})
