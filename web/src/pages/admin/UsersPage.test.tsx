import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { I18nProvider } from '../../i18n'
import { UsersPage } from './UsersPage'

function renderUsersPage() {
  return render(
    <I18nProvider>
      <UsersPage />
    </I18nProvider>,
  )
}

async function openDrawer() {
  const user = userEvent.setup()
  const trigger = screen.getByRole('button', { name: /Maya Chen.*maya@acme\.dev/ })
  await user.click(trigger)
  return { trigger, user, dialog: screen.getByRole('dialog') }
}

describe('UsersPage user drawer', () => {
  it('exposes labelled modal dialog semantics and focuses its first control', async () => {
    renderUsersPage()
    const { dialog } = await openDrawer()

    const headings = within(dialog).getAllByRole('heading')
    const title = headings.find((heading) => heading.textContent === 'User details')
    const profileName = headings.find((heading) => heading.textContent === 'Maya Chen')
    const description = dialog.querySelector('p')

    expect(title).toBeDefined()
    expect(profileName).toBeDefined()
    expect(description).not.toBeNull()
    expect(dialog).toHaveAttribute('role', 'dialog')
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveAttribute('aria-labelledby', `${title?.id} ${profileName?.id}`)
    expect(dialog).toHaveAttribute('aria-describedby', description?.id)
    expect(dialog).toHaveAccessibleName('User details Maya Chen')
    expect(dialog).toHaveAccessibleDescription('maya@acme.dev')
    expect(within(dialog).getByRole('button', { name: 'Close user details' })).toHaveFocus()
  })

  it('wraps Tab and Shift+Tab at the drawer boundaries', async () => {
    renderUsersPage()
    const { dialog } = await openDrawer()
    const close = within(dialog).getByRole('button', { name: 'Close user details' })
    const reset = within(dialog).getByRole('button', { name: 'Reset credentials' })
    const suspend = within(dialog).getByRole('button', { name: 'Suspend user' })

    await userEvent.setup().tab()
    expect(reset).toHaveFocus()
    await userEvent.setup().tab()
    expect(suspend).toHaveFocus()

    fireEvent.keyDown(suspend, { code: 'Tab', key: 'Tab' })
    expect(close).toHaveFocus()
    fireEvent.keyDown(close, { code: 'Tab', key: 'Tab', shiftKey: true })
    expect(suspend).toHaveFocus()
  })

  it('closes on Escape and restores focus to the user trigger', async () => {
    renderUsersPage()
    const { trigger, user } = await openDrawer()

    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })

  it('keeps internal mousedown open and closes on drawer backdrop mousedown', async () => {
    renderUsersPage()
    const { trigger, dialog } = await openDrawer()
    const backdrop = dialog.parentElement

    expect(backdrop).not.toBeNull()
    fireEvent.mouseDown(dialog)
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.mouseDown(backdrop as HTMLElement)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })
})
