import { useState, type ReactNode } from 'react'
import {
  Activity,
  AppWindow,
  Bell,
  ChevronDown,
  CircleHelp,
  Clock3,
  Command,
  ExternalLink,
  LayoutDashboard,
  Menu,
  Search,
  ScrollText,
  Settings2,
  ShieldCheck,
  UsersRound,
  X,
} from 'lucide-react'
import { Link, NavLink } from '../router'
import { useLocation } from '../router-context'
import { useI18n, type TranslationKey } from '../i18n'
import { Brand } from './Brand'
import { LanguageSwitcher } from './LanguageSwitcher'
import type { IconComponent } from './ui'

type NavItem = {
  labelKey: TranslationKey
  path: string
  icon: IconComponent
  end?: boolean
  badge?: string
}

const workspaceNavigation: NavItem[] = [
  { labelKey: 'admin.nav.overview', path: '/admin', icon: LayoutDashboard, end: true },
  { labelKey: 'admin.nav.users', path: '/admin/users', icon: UsersRound },
  { labelKey: 'admin.nav.applications', path: '/admin/applications', icon: AppWindow, badge: '8' },
]

const securityNavigation: NavItem[] = [
  { labelKey: 'admin.nav.sessions', path: '/admin/sessions', icon: Clock3 },
  { labelKey: 'admin.nav.audit', path: '/admin/audit', icon: ScrollText },
  { labelKey: 'admin.nav.settings', path: '/admin/settings', icon: Settings2 },
]

const routeTitles: Array<[string, TranslationKey]> = [
  ['/admin/applications/new', 'admin.nav.newApplication'],
  ['/admin/applications', 'admin.nav.applications'],
  ['/admin/sessions', 'admin.nav.sessions'],
  ['/admin/settings', 'admin.nav.settings'],
  ['/admin/audit', 'admin.nav.audit'],
  ['/admin/users', 'admin.nav.users'],
  ['/admin', 'admin.nav.overview'],
]

function NavGroup({
  label,
  items,
  onNavigate,
}: {
  label: string
  items: NavItem[]
  onNavigate: () => void
}) {
  const { t } = useI18n()

  return (
    <div className="sidebar-group">
      <span className="sidebar-group__label">{label}</span>
      <nav className="sidebar-nav" aria-label={label}>
        {items.map((item) => {
          const Icon = item.icon
          return (
            <NavLink
              className={({ isActive }) => `sidebar-link ${isActive ? 'is-active' : ''}`}
              end={item.end}
              key={item.path}
              onClick={onNavigate}
              to={item.path}
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{t(item.labelKey)}</span>
              {item.badge && <span className="sidebar-link__badge">{item.badge}</span>}
            </NavLink>
          )
        })}
      </nav>
    </div>
  )
}

function Sidebar({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { t } = useI18n()

  return (
    <>
      <aside className={`admin-sidebar ${isOpen ? 'is-open' : ''}`}>
        <div className="admin-sidebar__brand">
          <Link to="/admin" onClick={onClose} aria-label={t('admin.sidebar.home')}>
            <Brand />
          </Link>
          <button className="sidebar-close" type="button" onClick={onClose} aria-label={t('admin.sidebar.closeMenu')}>
            <X size={19} />
          </button>
        </div>

        <button className="workspace-switcher" type="button">
          <span className="workspace-switcher__mark">OI</span>
          <span>
            <strong>OneIssuer</strong>
            <small>{t('admin.sidebar.defaultWorkspace')}</small>
          </span>
          <ChevronDown size={15} />
        </button>

        <div className="admin-sidebar__nav">
          <NavGroup label={t('admin.nav.workspace')} items={workspaceNavigation} onNavigate={onClose} />
          <NavGroup label={t('admin.nav.security')} items={securityNavigation} onNavigate={onClose} />
        </div>

        <div className="admin-sidebar__bottom">
          <Link className="sidebar-preview" to="/account" onClick={onClose}>
            <UsersRound size={16} />
            {t('admin.sidebar.previewAccount')}
          </Link>
          <Link className="sidebar-preview" to="/login" onClick={onClose}>
            <ExternalLink size={16} />
            {t('admin.sidebar.previewSignIn')}
          </Link>
          <div className="system-health">
            <span className="system-health__icon">
              <Activity size={16} />
            </span>
            <span>
              <strong>{t('admin.sidebar.systemOperational')}</strong>
              <small>{t('admin.sidebar.systemServices')}</small>
            </span>
            <span className="system-health__dot" />
          </div>
        </div>
      </aside>
      {isOpen && <button className="sidebar-overlay" onClick={onClose} aria-label={t('admin.sidebar.closeMenu')} />}
    </>
  )
}

function Topbar({ onOpenMenu }: { onOpenMenu: () => void }) {
  const location = useLocation()
  const { t } = useI18n()
  const titleKey = routeTitles.find(([path]) => location.pathname.startsWith(path))?.[1] ?? 'admin.nav.overview'

  return (
    <header className="admin-topbar">
      <div className="admin-topbar__context">
        <button className="mobile-menu" type="button" onClick={onOpenMenu} aria-label={t('admin.topbar.openMenu')}>
          <Menu size={20} />
        </button>
        <ShieldCheck size={16} />
        <span>{t('admin.topbar.console')}</span>
        <span className="breadcrumb-separator">/</span>
        <strong>{t(titleKey)}</strong>
      </div>

      <div className="admin-topbar__actions">
        <label className="global-search">
          <Search size={16} />
          <input aria-label={t('admin.topbar.search')} name="global-search" placeholder={t('admin.topbar.searchPlaceholder')} />
          <kbd>
            <Command size={11} /> K
          </kbd>
        </label>
        <LanguageSwitcher />
        <button className="topbar-icon topbar-icon--help" type="button" aria-label={t('admin.topbar.help')}>
          <CircleHelp size={19} />
        </button>
        <button className="topbar-icon topbar-icon--notification" type="button" aria-label={t('admin.topbar.notifications')}>
          <Bell size={19} />
          <span />
        </button>
        <Link className="admin-account" to="/account">
          <span className="admin-account__avatar">AL</span>
          <span className="admin-account__copy">
            <strong>Alex Lin</strong>
            <small>{t('admin.topbar.owner')}</small>
          </span>
          <ChevronDown size={14} />
        </Link>
      </div>
    </header>
  )
}

export function AdminShell({ children }: { children?: ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="admin-shell">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="admin-main">
        <Topbar onOpenMenu={() => setSidebarOpen(true)} />
        <main className="admin-content">{children}</main>
      </div>
    </div>
  )
}
