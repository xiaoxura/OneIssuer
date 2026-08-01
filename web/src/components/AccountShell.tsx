import { useEffect, useRef, type ReactNode } from 'react'
import { AppWindow, LayoutDashboard, LogOut, Monitor, ShieldCheck } from 'lucide-react'
import { Link, NavLink } from '../router'
import { useLocation } from '../router-context'
import { useI18n } from '../i18n'
import { Brand } from './Brand'
import { LanguageSwitcher } from './LanguageSwitcher'

const accountNavigation = [
  { labelKey: 'account.nav.overview', path: '/account', icon: LayoutDashboard, end: true },
  { labelKey: 'account.nav.security', path: '/account/security', icon: ShieldCheck },
  { labelKey: 'account.nav.applications', path: '/account/applications', icon: AppWindow },
  { labelKey: 'account.nav.sessions', path: '/account/sessions', icon: Monitor },
] as const

export function AccountShell({ children, name }: { children: ReactNode; name: string }) {
  const { pathname } = useLocation()
  const { t } = useI18n()
  const accountNavRef = useRef<HTMLElement>(null)
  const initials = name.split(/\s+/).slice(0, 2).map((part) => part[0]).join('').toUpperCase()

  useEffect(() => {
    const navigation = accountNavRef.current
    const activeLink = navigation?.querySelector<HTMLElement>('.is-active')
    if (!navigation || !activeLink || navigation.scrollWidth <= navigation.clientWidth) return

    const targetLeft = activeLink.offsetLeft - (navigation.clientWidth - activeLink.offsetWidth) / 2
    navigation.scrollTo({ left: Math.max(0, targetLeft), behavior: 'auto' })
  }, [pathname])

  return (
    <div className="account-shell">
      <header className="account-topbar">
        <div className="account-topbar__inner">
          <Link className="account-topbar__brand" to="/account" aria-label={t('account.shell.home')}>
            <Brand />
          </Link>

          <div className="account-topbar__actions">
            <Link className="account-admin-link" to="/admin">
              <ShieldCheck size={16} />
              <span>{t('account.shell.adminConsole')}</span>
            </Link>
            <LanguageSwitcher />
            <div className="account-user-chip" role="group" aria-label={t('account.shell.signedInAs', { name })}>
              <span className="account-user-chip__avatar">{initials}</span>
              <span className="account-user-chip__copy">
                <strong>{name}</strong>
                <small>{t('account.shell.personalAccount')}</small>
              </span>
            </div>
            <Link className="account-signout" to="/login" aria-label={t('account.shell.signOut')}>
              <LogOut size={18} />
            </Link>
          </div>
        </div>
      </header>

      <div className="account-workspace">
        <aside className="account-sidebar">
          <div className="account-sidebar__header">
            <strong>{t('account.nav.label')}</strong>
            <small>{t('account.nav.description')}</small>
          </div>

          <nav ref={accountNavRef} className="account-primary-nav" aria-label={t('account.nav.aria')}>
            {accountNavigation.map((item) => {
              const Icon = item.icon
              return (
                <NavLink
                  className={({ isActive }) => isActive ? 'is-active' : ''}
                  end={'end' in item ? item.end : false}
                  key={item.path}
                  to={item.path}
                >
                  <Icon size={18} strokeWidth={1.8} />
                  <span>{t(item.labelKey)}</span>
                </NavLink>
              )
            })}
          </nav>

          <div className="account-sidebar__security">
            <span><ShieldCheck size={18} /></span>
            <div>
              <strong>{t('account.protected')}</strong>
              <small>{t('account.securityChecked')}</small>
            </div>
          </div>
        </aside>

        <div className="account-page-column">
          <main className="account-main">{children}</main>

          <footer className="account-footer">
            <span>© 2026 OneIssuer</span>
            <nav aria-label={t('account.footer.aria')}>
              <a href="#privacy">{t('account.footer.privacy')}</a>
              <a href="#terms">{t('account.footer.terms')}</a>
              <a href="#help">{t('account.footer.help')}</a>
            </nav>
          </footer>
        </div>
      </div>
    </div>
  )
}
