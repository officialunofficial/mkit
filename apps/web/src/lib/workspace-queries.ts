import { queryOptions } from '@tanstack/react-query'
import { workspaceRead, type WorkspaceFileContent, type WorkspaceSummary, type WorkspaceView } from './workspace-client'

export type WorkspaceSession = { id: string; publicKey: string } | null | undefined
export const workspaceKeys = {
  scope: (session: WorkspaceSession) => ['workspaces', session?.id ?? 'public', session?.publicKey ?? ''] as const,
  view: (id: string, session: WorkspaceSession, version: string | null = null) =>
    [...workspaceKeys.scope(session), id, 'view', version] as const,
  file: (id: string, session: WorkspaceSession, path: string, version: string | null, hash: string | null) =>
    [...workspaceKeys.scope(session), id, 'file', path, version, version ? 0 : hash] as const,
}

export function workspaceListOptions(session: WorkspaceSession) {
  return queryOptions({
    queryKey: [...workspaceKeys.scope(session), 'list'],
    queryFn: ({ signal }) => workspaceRead<{ workspaces: WorkspaceSummary[] }>('', signal),
    enabled: session !== undefined,
  })
}

export function workspaceViewOptions(id: string, session: WorkspaceSession, version: string | null = null) {
  return queryOptions({
    queryKey: workspaceKeys.view(id, session, version),
    queryFn: ({ signal }) =>
      workspaceRead<WorkspaceView>(
        `/${encodeURIComponent(id)}${version ? `?version=${encodeURIComponent(version)}` : ''}`,
        signal,
      ),
    enabled: !!id && session !== undefined,
    refetchInterval: version
      ? false
      : (query) => {
          const status = query.state.data?.task?.status
          return status === 'queued' || status === 'running' ? 2000 : 5000
        },
  })
}

export function workspaceFileOptions(
  view: WorkspaceView,
  session: WorkspaceSession,
  path: string,
  version: string | null,
) {
  return queryOptions({
    queryKey: workspaceKeys.file(
      view.workspace.id,
      session,
      path,
      version,
      view.files.find((file) => file.path === path)?.hash ?? null,
    ),
    queryFn: ({ signal }) =>
      workspaceRead<WorkspaceFileContent>(
        `/${encodeURIComponent(view.workspace.id)}/file?path=${encodeURIComponent(path)}${version ? `&version=${encodeURIComponent(version)}` : ''}`,
        signal,
      ),
    enabled: !!path && session !== undefined,
  })
}
