import { useEffect, useRef, type RefObject } from 'react'

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

function focusableElements(container: HTMLElement) {
  return Array.from(container.querySelectorAll<HTMLElement>(focusableSelector)).filter(
    (element) => element.getAttribute('aria-hidden') !== 'true' && !element.closest('[inert]'),
  )
}

export function useDialogFocus<T extends HTMLElement>(onClose: () => void): RefObject<T | null> {
  const dialogRef = useRef<T>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (typeof document === 'undefined') return

    const currentDialog = dialogRef.current
    if (!currentDialog) return
    const dialog: HTMLElement = currentDialog

    const returnFocusTo = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const focusable = focusableElements(dialog)
    const preferredFocus = dialog.querySelector<HTMLElement>('[autofocus], [data-dialog-initial-focus]')
    ;(preferredFocus ?? focusable[0] ?? dialog).focus({ preventScroll: true })

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault()
        onCloseRef.current()
        return
      }

      if (event.key !== 'Tab') return

      const currentFocusable = focusableElements(dialog)
      if (currentFocusable.length === 0) {
        event.preventDefault()
        dialog.focus({ preventScroll: true })
        return
      }

      const first = currentFocusable[0]
      const last = currentFocusable[currentFocusable.length - 1]
      const active = document.activeElement

      if (event.shiftKey && (active === first || !dialog.contains(active))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      if (returnFocusTo?.isConnected) returnFocusTo.focus({ preventScroll: true })
    }
  }, [])

  return dialogRef
}
