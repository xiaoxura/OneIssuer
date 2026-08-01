import { useState } from 'react'
import { AppWindow, CircleCheck, ExternalLink, ShieldCheck } from 'lucide-react'
import { AccountShell } from '../../components/AccountShell'
import { Avatar } from '../../components/ui'
import { useI18n } from '../../i18n'
import { initialApplications } from './data'

export function AccountApplicationsPage() {
  const { formatRelativeTime, t } = useI18n()
  const [applications, setApplications] = useState(initialApplications)
  const [notice, setNotice] = useState<string | null>(null)

  function revokeApplication(id: string) {
    setApplications((current) => current.filter((application) => application.id !== id))
    setNotice(t('account.apps.revoked'))
    window.setTimeout(() => setNotice(null), 2200)
  }

  return (
    <AccountShell name="Alex Lin">
      <header className="account-route-header">
        <div>
          <span className="account-eyebrow">{t('account.apps.eyebrow')}</span>
          <h1>{t('account.apps.title')}</h1>
          <p>{t('account.apps.pageDescription')}</p>
        </div>
        <span className="account-count-badge">{t('account.apps.connectedCount', { count: applications.length })}</span>
      </header>

      {applications.length > 0 ? (
        <section className="account-app-grid" aria-label={t('account.apps.title')}>
          {applications.map((application) => (
            <article className="account-app-card" key={application.id}>
              <header>
                <Avatar initials={application.initials} size="medium" tone={application.tone} />
                <div><h2>{application.name}</h2><p>{t(application.typeKey)}</p></div>
                <a href={`#${application.id}`} aria-label={t('account.apps.openAria', { application: application.name })}>
                  <ExternalLink size={16} />
                </a>
              </header>
              <div className="account-app-card__body">
                <span className="account-app-card__label">{t('account.apps.permissions')}</span>
                <div className="account-scope-list">
                  {application.scopes.map((scope) => <span key={scope}>{t(scope)}</span>)}
                </div>
                <div className="account-app-card__trust">
                  <ShieldCheck size={16} />
                  <span><strong>{t('account.apps.approved')}</strong><small>{t('account.apps.approvedDescription')}</small></span>
                </div>
              </div>
              <footer>
                <span><small>{t('account.apps.lastUsed')}</small><strong>{formatRelativeTime(application.lastUsed.value, application.lastUsed.unit)}</strong></span>
                <button
                  aria-label={t('account.apps.revokeAria', { application: application.name })}
                  onClick={() => revokeApplication(application.id)}
                  type="button"
                >
                  {t('account.apps.revoke')}
                </button>
              </footer>
            </article>
          ))}
        </section>
      ) : (
        <section className="account-panel account-empty-state account-empty-state--page">
          <AppWindow size={24} />
          <strong>{t('account.apps.emptyTitle')}</strong>
          <span>{t('account.apps.emptyDescription')}</span>
        </section>
      )}

      <section className="account-wide-note">
        <ShieldCheck size={19} />
        <div><strong>{t('account.apps.controlTitle')}</strong><p>{t('account.apps.controlDescription')}</p></div>
      </section>

      {notice && <div className="account-toast" role="status"><CircleCheck size={17} />{notice}</div>}
    </AccountShell>
  )
}
