'use client'

import { useAuth } from './auth-provider'

/** Every surface shares the same ceremony, status, and server session. */
export function useIdentityActions() {
  return useAuth()
}
export type IdentityActions = ReturnType<typeof useIdentityActions>
