import { useMemo, useState, type FormEvent } from 'react'
import {
  AppWindow,
  Ban,
  CalendarDays,
  Download,
  KeyRound,
  Mail,
  MoreHorizontal,
  Search,
  Send,
  ShieldCheck,
  SlidersHorizontal,
  UserPlus,
  X,
} from 'lucide-react'
import { Avatar, Modal, PageHeader, StatusPill } from '../../components/ui'
import { users, type PrototypeUser, type UserStatus } from '../../data/mock'
import { useI18n, type TranslationKey } from '../../i18n'
import { MFA_KEYS, USER_STATUS_KEYS } from '../../i18n/domain'

type UserFilter = 'all' | UserStatus

const filters: UserFilter[] = ['all', 'active', 'invited', 'suspended']
const filterKeys: Record<UserFilter, TranslationKey> = {
  all: 'common.all',
  active: 'status.user.active',
  invited: 'status.user.invited',
  suspended: 'status.user.suspended',
}

function statusTone(status: UserStatus) {
  if (status === 'active') return 'success' as const
  if (status === 'invited') return 'info' as const
  return 'danger' as const
}

function UserDrawer({ user, onClose }: { user: PrototypeUser; onClose: () => void }) {
  const { formatDate, formatRelativeTime, t } = useI18n()

  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={onClose}>
      <aside
        aria-label={t('users.drawer.detailsFor', { name: user.name })}
        className="detail-drawer"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="detail-drawer__topbar">
          <span>{t('users.drawer.title')}</span>
          <button className="icon-button" type="button" onClick={onClose} aria-label={t('users.drawer.close')}><X size={18} /></button>
        </header>
        <div className="detail-drawer__profile">
          <Avatar initials={user.initials} tone={user.tone} size="large" />
          <h2>{user.name}</h2>
          <p>{user.email}</p>
          <StatusPill tone={statusTone(user.status)}>{t(USER_STATUS_KEYS[user.status])}</StatusPill>
        </div>

        <div className="detail-drawer__section">
          <h3>{t('users.drawer.account')}</h3>
          <dl className="detail-list">
            <div><dt><Mail size={15} />{t('users.drawer.email')}</dt><dd>{user.email}</dd></div>
            <div><dt><KeyRound size={15} />MFA</dt><dd>{t(MFA_KEYS[user.mfa])}</dd></div>
            <div><dt><CalendarDays size={15} />{t('users.drawer.created')}</dt><dd>{formatDate(user.created, { year: 'numeric', month: 'short', day: 'numeric' })}</dd></div>
            <div><dt><AppWindow size={15} />{t('users.drawer.applications')}</dt><dd>{t('users.drawer.connectedCount', { count: user.applications })}</dd></div>
          </dl>
        </div>

        <div className="detail-drawer__section">
          <h3>{t('users.drawer.stableIdentity')}</h3>
          <div className="code-value"><span>{t('users.drawer.subject')}</span><code>{user.id}</code></div>
          <div className="code-value"><span>{t('users.drawer.issuer')}</span><code>https://id.oneissuer.dev</code></div>
        </div>

        <div className="detail-drawer__activity">
          <span><i />{t('users.drawer.lastActive')}</span>
          <strong>{user.lastSeen ? formatRelativeTime(user.lastSeen.value, user.lastSeen.unit) : t('common.never')}</strong>
        </div>

        <footer className="detail-drawer__footer">
          <button className="button button--secondary" type="button"><KeyRound size={16} />{t('users.drawer.resetCredentials')}</button>
          <button className="button button--danger-soft" type="button"><Ban size={16} />{t('users.drawer.suspend')}</button>
        </footer>
      </aside>
    </div>
  )
}

export function UsersPage() {
  const { formatNumber, formatRelativeTime, t } = useI18n()
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<UserFilter>('all')
  const [selectedUser, setSelectedUser] = useState<PrototypeUser | null>(null)
  const [inviteOpen, setInviteOpen] = useState(false)

  const filteredUsers = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    return users.filter((user) => {
      const matchesStatus = filter === 'all' || user.status === filter
      const matchesQuery = !normalizedQuery || `${user.name} ${user.email}`.toLowerCase().includes(normalizedQuery)
      return matchesStatus && matchesQuery
    })
  }, [filter, query])

  function submitInvite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setInviteOpen(false)
  }

  return (
    <>
      <PageHeader
        eyebrow={t('users.eyebrow')}
        title={t('users.title')}
        description={t('users.description')}
        actions={
          <>
            <button className="button button--secondary" type="button"><Download size={16} />{t('users.export')}</button>
            <button className="button button--primary" onClick={() => setInviteOpen(true)} type="button"><UserPlus size={17} />{t('users.add')}</button>
          </>
        }
      />

      <section className="panel directory-panel">
        <div className="directory-toolbar">
          <label className="table-search">
            <Search size={16} />
            <input aria-label={t('users.searchPlaceholder')} name="user-search" onChange={(event) => setQuery(event.target.value)} placeholder={t('users.searchPlaceholder')} value={query} />
          </label>
          <div className="filter-tabs" role="group" aria-label={t('users.filterAria')}>
            {filters.map((item) => (
              <button className={filter === item ? 'is-active' : ''} key={item} onClick={() => setFilter(item)} type="button">
                {t(filterKeys[item])}
                {item !== 'all' && <span>{users.filter((user) => user.status === item).length}</span>}
              </button>
            ))}
          </div>
          <button className="button button--tertiary toolbar-filter" type="button"><SlidersHorizontal size={16} />{t('users.moreFilters')}</button>
        </div>

        <div className="table-scroll">
          <table className="data-table users-table">
            <thead>
              <tr><th className="checkbox-cell"><input aria-label={t('users.selectAll')} type="checkbox" /></th><th>{t('users.user')}</th><th>{t('users.status')}</th><th>MFA</th><th>{t('users.applications')}</th><th>{t('users.lastActive')}</th><th><span className="sr-only">{t('common.actions')}</span></th></tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => (
                <tr key={user.id} onClick={() => setSelectedUser(user)}>
                  <td className="checkbox-cell" onClick={(event) => event.stopPropagation()}><input aria-label={t('users.selectUser', { name: user.name })} type="checkbox" /></td>
                  <td><button className="user-cell user-cell--button" onClick={(event) => { event.stopPropagation(); setSelectedUser(user) }} type="button"><Avatar initials={user.initials} tone={user.tone} /><span><strong>{user.name}</strong><small>{user.email}</small></span></button></td>
                  <td><StatusPill tone={statusTone(user.status)}>{t(USER_STATUS_KEYS[user.status])}</StatusPill></td>
                  <td><span className={user.mfa === 'notEnrolled' ? 'mfa-state mfa-state--missing' : 'mfa-state'}><ShieldCheck size={15} />{t(MFA_KEYS[user.mfa])}</span></td>
                  <td><span className="application-count"><AppWindow size={15} />{user.applications}</span></td>
                  <td className="muted-cell">{user.lastSeen ? formatRelativeTime(user.lastSeen.value, user.lastSeen.unit) : t('common.never')}</td>
                  <td><button className="table-action" onClick={(event) => event.stopPropagation()} type="button" aria-label={t('users.moreActions', { name: user.name })}><MoreHorizontal size={18} /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <footer className="table-footer">
          <span>{t('users.showing', { shown: formatNumber(filteredUsers.length), total: formatNumber(1284) })}</span>
          <div className="pagination"><button disabled type="button">{t('common.previous')}</button><button className="is-active" type="button">1</button><button type="button">2</button><button type="button">3</button><span>…</span><button type="button">65</button><button type="button">{t('common.next')}</button></div>
        </footer>
      </section>

      {selectedUser && <UserDrawer user={selectedUser} onClose={() => setSelectedUser(null)} />}

      {inviteOpen && (
        <Modal title={t('users.modal.title')} description={t('users.modal.description')} onClose={() => setInviteOpen(false)}>
          <form className="modal-form" onSubmit={submitInvite}>
            <div className="form-grid form-grid--two">
              <label className="form-field"><span>{t('users.modal.firstName')}</span><span className="input-shell"><input placeholder="Maya" required /></span></label>
              <label className="form-field"><span>{t('users.modal.lastName')}</span><span className="input-shell"><input placeholder="Chen" required /></span></label>
            </div>
            <label className="form-field"><span>{t('users.modal.email')}</span><span className="input-shell"><Mail size={17} /><input placeholder="maya@company.com" required type="email" /></span></label>
            <label className="checkbox-row"><input defaultChecked type="checkbox" /><span>{t('users.modal.welcomeEmail')}</span></label>
            <footer className="modal__actions">
              <button className="button button--secondary" onClick={() => setInviteOpen(false)} type="button">{t('common.cancel')}</button>
              <button className="button button--primary" type="submit"><Send size={16} />{t('users.modal.create')}</button>
            </footer>
          </form>
        </Modal>
      )}
    </>
  )
}
