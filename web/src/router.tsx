import { useEffect, useMemo, useState, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react'
import { RouterContext, useLocation, useNavigate, type RouterContextValue } from './router-context'

export function RouterProvider({ children }: { children: ReactNode }) {
  const [pathname, setPathname] = useState(() => window.location.pathname)

  useEffect(() => {
    const handlePopState = () => setPathname(window.location.pathname)
    window.addEventListener('popstate', handlePopState)
    return () => window.removeEventListener('popstate', handlePopState)
  }, [])

  const value = useMemo<RouterContextValue>(
    () => ({
      pathname,
      navigate: (to, options) => {
        if (options?.replace) window.history.replaceState(null, '', to)
        else window.history.pushState(null, '', to)
        setPathname(window.location.pathname)
        window.scrollTo({ top: 0, behavior: 'instant' })
      },
    }),
    [pathname],
  )

  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>
}

type LinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> & {
  to: string
}

export function Link({ to, onClick, target, children, ...props }: LinkProps) {
  const navigate = useNavigate()

  function handleClick(event: MouseEvent<HTMLAnchorElement>) {
    onClick?.(event)
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey ||
      target === '_blank'
    ) return

    event.preventDefault()
    navigate(to)
  }

  return <a {...props} href={to} onClick={handleClick} target={target}>{children}</a>
}

type NavLinkProps = Omit<LinkProps, 'className'> & {
  className?: string | ((state: { isActive: boolean }) => string)
  end?: boolean
}

export function NavLink({ className, end = false, to, ...props }: NavLinkProps) {
  const { pathname } = useLocation()
  const isActive = end ? pathname === to : pathname === to || pathname.startsWith(`${to}/`)
  const resolvedClassName = typeof className === 'function' ? className({ isActive }) : className
  return <Link {...props} className={resolvedClassName} to={to} />
}

export function Redirect({ to }: { to: string }) {
  const navigate = useNavigate()

  useEffect(() => navigate(to, { replace: true }), [navigate, to])
  return null
}
