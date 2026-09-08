import type { ReactNode } from 'react'

/** One placeholder per field; the accessible status is supplied by the container. */
export function Skeleton({ className = '' }: { className?: string }) {
  return <div aria-hidden data-motion='essential' className={`skeleton ${className}`} />
}

function LoadingRegion({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div role='status' aria-label={label}>
      <span className='sr-only'>{label}</span>
      <div aria-hidden>{children}</div>
    </div>
  )
}

export function LobbyRowsSkeleton() {
  return (
    <LoadingRegion label='Loading lobby activity'>
      <div className='space-y-6 px-4 py-4'>
        {[0, 1, 2, 3].map((row) => (
          <div key={row} className='flex items-start gap-3'>
            <Skeleton className='size-6 shrink-0' />
            <div className='flex-1 space-y-2'>
              <Skeleton className='h-3 w-24' />
              <Skeleton className={`h-4 ${row % 2 ? 'w-2/3' : 'w-5/6'}`} />
            </div>
          </div>
        ))}
      </div>
    </LoadingRegion>
  )
}

export function LobbySkeleton() {
  return (
    <section className='overflow-hidden rounded-md border border-hairline' aria-label='Live lobby'>
      <div className='flex items-center gap-2 border-b border-hairline px-4 py-3'>
        <span className='size-2 rounded-full bg-(--status-neutral-fg)' aria-hidden />
        <h2 className='ds-h2'>Live lobby</h2>
      </div>
      <div className='h-96 py-1'>
        <LobbyRowsSkeleton />
      </div>
      <div className='flex items-center gap-3 border-t border-hairline px-4 py-3' aria-hidden>
        <Skeleton className='h-8 w-44' />
      </div>
    </section>
  )
}

function Fields({ rows = 3 }: { rows?: number }) {
  return (
    <div className='space-y-4'>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className='space-y-2'>
          <Skeleton className='h-3 w-24' />
          <Skeleton className='h-8 w-full' />
        </div>
      ))}
    </div>
  )
}

export type ConceptKind = 'hash' | 'tree' | 'sign' | 'streaming' | 'push' | 'attest'

export function ConceptSkeleton({ kind }: { kind: ConceptKind }) {
  return (
    <LoadingRegion label='Loading interactive demo'>
      <ConceptPlaceholder kind={kind} />
    </LoadingRegion>
  )
}

export function MultiplayerSkeleton() {
  return (
    <LoadingRegion label='Loading shared repository'>
      <div className='space-y-8'>
        <div className='space-y-4 rounded-md border border-hairline p-4 sm:p-5'>
          <Skeleton className='h-8 w-48' />
          <Skeleton className='h-4 w-2/3' />
        </div>
        <div className='grid gap-8 lg:grid-cols-2'>
          <div className='space-y-4'>
            <h2 className='ds-h3'>Branches</h2>
            <Fields />
          </div>
          <Fields />
        </div>
      </div>
    </LoadingRegion>
  )
}

function ConceptPlaceholder({ kind }: { kind: ConceptKind }) {
  switch (kind) {
    case 'hash':
      return (
        <div className='space-y-6'>
          <Fields rows={2} />
          <div className='flex gap-3'>
            <Skeleton className='size-16' />
            <Skeleton className='h-4 w-1/2' />
          </div>
        </div>
      )
    case 'tree':
      return (
        <div className='flex flex-col-reverse gap-10 lg:grid lg:grid-cols-[minmax(0,20rem)_1fr] lg:gap-12'>
          <Fields />
          <div className='flex h-56 flex-col items-center justify-center gap-8'>
            <Skeleton className='size-8' />
            <div className='flex gap-8'>
              <Skeleton className='size-8' />
              <Skeleton className='size-8' />
              <Skeleton className='size-8' />
            </div>
          </div>
        </div>
      )
    case 'sign':
      return (
        <div className='space-y-6'>
          <Skeleton className='h-6 w-40' />
          <Fields rows={1} />
          <Skeleton className='h-8 w-16' />
        </div>
      )
    case 'streaming':
      return (
        <div className='space-y-4'>
          <Skeleton className='h-4 w-40' />
          <Skeleton className='size-40' />
          <Skeleton className='h-6 w-full' />
          <Skeleton className='h-8 w-36' />
        </div>
      )
    case 'push':
      return (
        <div className='space-y-5 rounded-md border border-hairline p-5'>
          <Skeleton className='h-5 w-48' />
          <div className='min-h-[11rem] space-y-4'>
            <Skeleton className='h-6 w-full' />
            <Skeleton className='h-4 w-1/2' />
          </div>
          <div className='flex justify-between border-t border-hairline pt-4'>
            <Skeleton className='h-8 w-20' />
            <Skeleton className='h-8 w-24' />
          </div>
        </div>
      )
    case 'attest':
      return (
        <div className='space-y-6'>
          <Skeleton className='h-6 w-40' />
          <Fields />
          <Skeleton className='h-4 w-2/3' />
        </div>
      )
  }
}

export function CommitSkeleton() {
  return (
    <LoadingRegion label='Loading commit details'>
      <Fields />
    </LoadingRegion>
  )
}
