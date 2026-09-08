'use client'

import { useVirtualizer } from '@tanstack/react-virtual'
import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef as useReactRef, useState } from 'react'
import { HOVER_BORDER } from '../multiplayer/shared'

const useIsomorphicLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect

export function VirtualFeed<T extends { key: string }>({
  items,
  renderItem,
  emptyContent,
}: {
  items: T[]
  renderItem: (item: T, previous: T | undefined) => ReactNode
  emptyContent: ReactNode
}) {
  const scrollRef = useReactRef<HTMLDivElement>(null)
  const [atBottom, setAtBottom] = useState(true)
  const didInitRef = useReactRef(false)
  const getItemKey = useCallback((index: number) => items[index]!.key, [items])
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 56,
    getItemKey,
    overscan: 6,
    paddingStart: 4,
    paddingEnd: 4,
    anchorTo: 'end',
    // Automatic following is immediate, including reconnect/resume batches.
    // The virtualizer preserves a keyed row when the reader is in history.
    followOnAppend: true,
    scrollEndThreshold: 24,
    onChange: (instance) => setAtBottom(instance.isAtEnd()),
  })

  // Data may arrive after mount. Initialize once, then let TanStack handle
  // measurement corrections and append/prepend anchoring without frame loops.
  useIsomorphicLayoutEffect(() => {
    if (!didInitRef.current && items.length > 0) {
      didInitRef.current = true
      virtualizer.scrollToEnd()
    }
  }, [items.length, virtualizer])

  const onScroll = () => setAtBottom(virtualizer.isAtEnd())
  const jumpToLatest = () => virtualizer.scrollToEnd()

  const empty = items.length === 0
  return (
    <div className='relative'>
      {/* FIXED height (not max-h): the virtualizer needs a definite viewport, and a
          fixed box means the list scrolls internally instead of growing the page
          as messages arrive. */}
      <div
        ref={scrollRef}
        onScroll={onScroll}
        role='region'
        aria-label='Lobby activity'
        tabIndex={0}
        className='h-96 overflow-y-auto overscroll-contain scroll-auto [overflow-anchor:none]'
      >
        {empty ? (
          emptyContent
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {virtualizer.getVirtualItems().map((vrow) => {
              const item = items[vrow.index]
              if (!item) return null
              const prev = vrow.index > 0 ? items[vrow.index - 1] : undefined
              return (
                <div
                  key={vrow.key}
                  data-index={vrow.index}
                  ref={virtualizer.measureElement}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    transform: `translateY(${vrow.start}px)`,
                  }}
                >
                  {renderItem(item, prev)}
                </div>
              )
            })}
          </div>
        )}
      </div>
      <button
        type='button'
        onClick={jumpToLatest}
        aria-hidden={atBottom || empty}
        tabIndex={atBottom || empty ? -1 : 0}
        className={`absolute right-3 bottom-3 inline-flex h-8 items-center rounded-full border border-hairline bg-bg/90 px-3 text-xs shadow-sm backdrop-blur transition-[opacity,scale,border-color] duration-(--duration-fast) ease-standard before:absolute before:inset-x-0 before:-inset-y-1 before:content-[""] ${HOVER_BORDER} active:scale-[0.96] ${
          atBottom || empty ? 'pointer-events-none scale-95 opacity-0' : 'opacity-100'
        }`}
      >
        ↓ Latest
      </button>
    </div>
  )
}
