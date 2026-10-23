'use client'

import { useAuth } from './auth-provider'

/** Every surface shares the same ceremony, status, and local identity. */
export function useIdentityActions() {
  return useAuth()
}
export type IdentityActions = ReturnType<typeof useIdentityActions>
