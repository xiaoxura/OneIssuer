import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../i18n'
import { Modal } from './ui'

function ModalHarness() {
  const [open, setOpen] = useState(false)

  return (
    <>
      <button onClick={() => setOpen(true)} type="button">Open invite</button>
      {open && (
        <Modal
          description="Create an identity and send an optional welcome email."
          onClose={() => setOpen(false)}
          title="Add a user"
        >
          <form>
            <label>
              First name
              <input aria-label="First name" data-dialog-initial-focus />
            </label>
            <button type="button">Create user</button>
          </form>
        </Modal>
      )}
    </>
  )
}

function renderModal() {
  return render(
    <I18nProvider>
      <ModalHarness />
    </I18nProvider>,
  )
}

function getOpenButton() {
  return screen.getByRole('button', { name: 'Open invite' })
}

async function openModal() {
  const user = userEvent.setup()
  const trigger = getOpenButton()
  await user.click(trigger)
  return { trigger, user, dialog: screen.getByRole('dialog') }
}

describe('Modal', () => {
  it('exposes labelled dialog semantics and focuses the preferred control', async () => {
    renderModal()
    const { dialog } = await openModal()

    const title = within(dialog).getByRole('heading', { name: 'Add a user' })
    const description = within(dialog).getByText('Create an identity and send an optional welcome email.')

    expect(dialog).toHaveAttribute('role', 'dialog')
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveAttribute('aria-labelledby', title.id)
    expect(dialog).toHaveAttribute('aria-describedby', description.id)
    expect(dialog).toHaveAccessibleName('Add a user')
    expect(dialog).toHaveAccessibleDescription('Create an identity and send an optional welcome email.')
    expect(within(dialog).getByRole('textbox', { name: 'First name' })).toHaveFocus()
  })

  it('wraps forward and reverse Tab navigation within the dialog', async () => {
    renderModal()
    const { dialog } = await openModal()
    const preferred = within(dialog).getByRole('textbox', { name: 'First name' })
    const last = within(dialog).getByRole('button', { name: 'Create user' })
    const close = within(dialog).getByRole('button', { name: 'Close' })

    await userEvent.setup().tab()
    expect(last).toHaveFocus()
    fireEvent.keyDown(last, { code: 'Tab', key: 'Tab' })
    expect(close).toHaveFocus()

    fireEvent.keyDown(close, { code: 'Tab', key: 'Tab', shiftKey: true })
    expect(last).toHaveFocus()
    expect(preferred).not.toHaveFocus()
  })

  it('closes from Escape or backdrop mousedown but keeps internal mousedown open', async () => {
    const onClose = vi.fn()
    const user = userEvent.setup()
    const view = render(
      <I18nProvider>
        <Modal description="Description" onClose={onClose} title="Title">
          <button type="button">Action</button>
        </Modal>
      </I18nProvider>,
    )
    const dialog = screen.getByRole('dialog')
    const backdrop = dialog.parentElement

    expect(backdrop).not.toBeNull()
    fireEvent.mouseDown(dialog)
    expect(onClose).not.toHaveBeenCalled()

    await user.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(1)

    view.unmount()
    const secondOnClose = vi.fn()
    render(
      <I18nProvider>
        <Modal description="Description" onClose={secondOnClose} title="Title">
          <button type="button">Action</button>
        </Modal>
      </I18nProvider>,
    )
    const secondDialog = screen.getByRole('dialog')
    fireEvent.mouseDown(secondDialog.parentElement as HTMLElement)
    expect(secondOnClose).toHaveBeenCalledTimes(1)
  })

  it('restores focus to the trigger after closing', async () => {
    renderModal()
    const { trigger, user, dialog } = await openModal()

    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()

    await user.click(trigger)
    const reopenedDialog = screen.getByRole('dialog')
    await user.click(within(reopenedDialog).getByRole('button', { name: 'Close' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
    expect(dialog).not.toBeInTheDocument()
  })
})
