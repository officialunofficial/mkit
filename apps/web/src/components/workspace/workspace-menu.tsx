'use client'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { DotsThreeIcon, InfoIcon, ProhibitIcon } from '@phosphor-icons/react/ssr'
import { TopLayer, useOverlayContainer } from '../top-layer'

export function WorkspaceMenu({
  onDetails,
  onRevoke,
  canRevoke,
}: {
  onDetails: () => void
  onRevoke: () => void
  canRevoke: boolean
}) {
  const container = useOverlayContainer()
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button className='btn btn--ghost btn--small' aria-label='Project options'>
          <DotsThreeIcon size={20} aria-hidden />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal container={container}>
        <TopLayer>
          <DropdownMenu.Content className='ws-menu' align='end' sideOffset={6} collisionPadding={8}>
            <DropdownMenu.Item onSelect={onDetails}>
              <InfoIcon size={15} aria-hidden />
              Project details
            </DropdownMenu.Item>
            {canRevoke ? (
              <>
                <DropdownMenu.Separator />
                <DropdownMenu.Item onSelect={onRevoke}>
                  <ProhibitIcon size={15} aria-hidden />
                  Revoke agent access
                </DropdownMenu.Item>
              </>
            ) : null}
          </DropdownMenu.Content>
        </TopLayer>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}
