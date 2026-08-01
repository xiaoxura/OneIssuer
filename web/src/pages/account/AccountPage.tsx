import { useState, type FormEvent } from 'react'
import {
  AppWindow,
  AtSign,
  Check,
  CircleCheck,
  Clock3,
  Copy,
  ExternalLink,
  KeyRound,
  LogIn,
  Monitor,
  ShieldCheck,
  UserRound,
} from 'lucide-react'
import { AccountShell } from '../../components/AccountShell'
import { Avatar, Modal, StatusPill } from '../../components/ui'
import { Link } from '../../router'
import { useI18n } from '../../i18n'

export function AccountPage() {
  const { formatDate, formatRelativeTime, t } = useI18n()
  const [fullName, setFullName] = useState('Alex Lin')
  const [draftName, setDraftName] = useState(fullName)
  const [editingProfile, setEditingProfile] = useState(false)
  const [accountIdCopied, setAccountIdCopied] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const initials = fullName.split(/\s+/).slice(0, 2).map((part) => part[0]).join('').toUpperCase()

  function showNotice(message: string) {
    setNotice(message)
    window.setTimeout(() => setNotice(null), 2200)
  }

  async function copyAccountId() {
    await navigator.clipboard?.writeText('usr_01J2V8YQK7N4M6PX')
    setAccountIdCopied(true)
    window.setTimeout(() => setAccountIdCopied(false), 1800)
  }

  function openProfileEditor() {
    setDraftName(fullName)
    setEditingProfile(true)
  }

  function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFullName(draftName.trim() || fullName)
    setEditingProfile(false)
    showNotice(t('account.profile.saved'))
  }

  const overviewCards = [
    {
      icon: ShieldCheck,
      label: t('account.nav.security'),
      value: t('account.security.strong'),
      detail: t('account.overview.securityDetail'),
      path: '/account/security',
    },
    {
      icon: AppWindow,
      label: t('account.nav.applications'),
      value: t('account.overview.appsValue', { count: 3 }),
      detail: t('account.overview.appsDetail'),
      path: '/account/applications',
    },
    {
      icon: Monitor,
      label: t('account.nav.sessions'),
      value: t('account.overview.sessionsValue', { count: 3 }),
      detail: t('account.overview.sessionsDetail'),
      path: '/account/sessions',
    },
  ]

  const activity = [
    {
      icon: LogIn,
      title: t('account.overview.activity.signedIn'),
      detail: 'MacBook Pro · Chrome 138 · Shanghai',
      time: formatRelativeTime(-12, 'minute'),
    },
    {
      icon: AppWindow,
      title: t('account.overview.activity.authorized'),
      detail: 'Canvas Studio · profile',
      time: formatRelativeTime(-2, 'day'),
    },
    {
      icon: KeyRound,
      title: t('account.overview.activity.recoveryCodes'),
      detail: t('account.overview.activity.securityDetail'),
      time: formatRelativeTime(-7, 'day'),
    },
  ]

  return (
    <AccountShell name={fullName}>
      <section className="account-hero account-hero--compact">
        <div>
          <span className="account-eyebrow">{t('account.eyebrow')}</span>
          <h1>{t('account.title', { name: fullName.split(' ')[0] })}</h1>
          <p>{t('account.overview.description')}</p>
        </div>
        <div className="account-trust-card">
          <span className="account-trust-card__icon"><ShieldCheck size={20} /></span>
          <span>
            <strong>{t('account.protected')}</strong>
            <small>{t('account.securityChecked')}</small>
          </span>
          <CircleCheck size={18} />
        </div>
      </section>

      <div className="account-overview-grid">
        <section className="account-profile-card">
          <div className="account-profile-card__identity">
            <span className="account-profile-card__avatar">
              <Avatar initials={initials} size="large" tone="slate" />
              <span><Check size={12} /></span>
            </span>
            <h2>{fullName}</h2>
            <p>alex@oneissuer.dev</p>
            <StatusPill tone="success">{t('account.profile.emailVerified')}</StatusPill>
          </div>

          <button className="button button--secondary button--full" onClick={openProfileEditor} type="button">
            <UserRound size={16} /> {t('account.profile.edit')}
          </button>

          <dl className="account-profile-details">
            <div>
              <dt>{t('account.profile.accountId')}</dt>
              <dd>
                <code>usr_01J2…M6PX</code>
                <button onClick={copyAccountId} type="button" aria-label={t('account.profile.copyId')}>
                  {accountIdCopied ? <Check size={15} /> : <Copy size={15} />}
                </button>
              </dd>
            </div>
            <div>
              <dt>{t('account.profile.created')}</dt>
              <dd>{formatDate('2026-07-12T09:00:00+08:00', { year: 'numeric', month: 'short', day: 'numeric' })}</dd>
            </div>
            <div>
              <dt>{t('account.profile.accountType')}</dt>
              <dd>{t('account.shell.personalAccount')}</dd>
            </div>
          </dl>

          <div className="account-profile-privacy">
            <ShieldCheck size={17} />
            <span><strong>{t('account.privacy.title')}</strong><small>{t('account.privacy.description')}</small></span>
          </div>
        </section>

        <div className="account-overview-main">
          <section className="account-overview-cards" aria-label={t('account.overview.summaryAria')}>
            {overviewCards.map(({ detail, icon: Icon, label, path, value }) => (
              <Link to={path} key={path}>
                <span className="account-overview-card__icon"><Icon size={20} /></span>
                <span className="account-overview-card__label">{label}</span>
                <strong>{value}</strong>
                <small>{detail}</small>
                <span className="account-overview-card__link">{t('account.overview.viewDetails')} <ExternalLink size={13} /></span>
              </Link>
            ))}
          </section>

          <section className="account-panel account-activity-panel">
            <header className="account-panel__header account-panel__header--row">
              <div>
                <span className="account-panel__eyebrow">{t('account.overview.activity.eyebrow')}</span>
                <h2>{t('account.overview.activity.title')}</h2>
                <p>{t('account.overview.activity.description')}</p>
              </div>
              <Clock3 size={20} />
            </header>
            <div className="account-activity-list">
              {activity.map(({ detail, icon: Icon, time, title }) => (
                <article key={title}>
                  <span><Icon size={18} /></span>
                  <div><strong>{title}</strong><small>{detail}</small></div>
                  <time>{time}</time>
                </article>
              ))}
            </div>
          </section>

          <section className="account-data-card">
            <span><AtSign size={18} /></span>
            <div><strong>{t('account.data.title')}</strong><p>{t('account.data.description')}</p></div>
            <a href="#download">{t('account.data.download')} <ExternalLink size={14} /></a>
          </section>
        </div>
      </div>

      {editingProfile && (
        <Modal title={t('account.profile.editTitle')} description={t('account.profile.editDescription')} onClose={() => setEditingProfile(false)}>
          <form className="modal-form" onSubmit={saveProfile}>
            <label className="form-field">
              <span>{t('account.profile.fullName')}</span>
              <span className="input-shell"><UserRound size={17} /><input autoFocus name="full-name" value={draftName} onChange={(event) => setDraftName(event.target.value)} required /></span>
            </label>
            <label className="form-field">
              <span>{t('account.profile.emailAddress')}</span>
              <span className="input-shell"><AtSign size={17} /><input name="email" readOnly value="alex@oneissuer.dev" /></span>
              <small>{t('account.profile.emailHint')}</small>
            </label>
            <div className="modal__actions">
              <button className="button button--secondary" onClick={() => setEditingProfile(false)} type="button">{t('common.cancel')}</button>
              <button className="button button--primary" type="submit">{t('account.profile.save')}</button>
            </div>
          </form>
        </Modal>
      )}

      {notice && <div className="account-toast" role="status"><CircleCheck size={17} />{notice}</div>}
    </AccountShell>
  )
}
