import { useState } from 'react'
import { CircleCheck, Clock3, MapPin, ShieldCheck } from 'lucide-react'
import { AccountShell } from '../../components/AccountShell'
import { StatusPill } from '../../components/ui'
import { useI18n } from '../../i18n'
import { initialSessions } from './data'

export function AccountSessionsPage() {
  const { formatRelativeTime, t } = useI18n()
  const [sessions, setSessions] = useState(initialSessions)
  const [notice, setNotice] = useState<string | null>(null)

  function showNotice(message: string) {
    setNotice(message)
    window.setTimeout(() => setNotice(null), 2200)
  }

  function revokeSession(id: string) {
    setSessions((current) => current.filter((session) => session.id !== id))
    showNotice(t('account.sessions.revoked'))
  }

  function revokeOtherSessions() {
    setSessions((current) => current.filter((session) => session.current))
    showNotice(t('account.sessions.othersRevoked'))
  }

  const hasOtherSessions = sessions.some((session) => !session.current)

  return (
    <AccountShell name="Alex Lin">
      <header className="account-route-header">
        <div>
          <span className="account-eyebrow">{t('account.sessions.eyebrow')}</span>
          <h1>{t('account.sessions.title')}</h1>
          <p>{t('account.sessions.pageDescription')}</p>
        </div>
        {hasOtherSessions && (
          <button className="button button--secondary" onClick={revokeOtherSessions} type="button">
            {t('account.sessions.signOutOthers')}
          </button>
        )}
      </header>

      <section className="account-session-grid" aria-label={t('account.sessions.title')}>
        {sessions.map((session) => {
          const Icon = session.icon
          return (
            <article className={`account-session-card ${session.current ? 'is-current' : ''}`} key={session.id}>
              <header>
                <span><Icon size={22} /></span>
                <div><h2>{session.device}</h2><p>{session.platform}</p></div>
                {session.current && <StatusPill tone="success">{t('common.current')}</StatusPill>}
              </header>
              <dl>
                <div><dt><MapPin size={15} />{t('account.sessions.location')}</dt><dd>{t(session.locationKey)}</dd></div>
                <div><dt><Clock3 size={15} />{t('account.sessions.lastActive')}</dt><dd>{formatRelativeTime(session.lastActive.value, session.lastActive.unit)}</dd></div>
              </dl>
              <footer>
                {session.current ? (
                  <span className="account-current-session"><CircleCheck size={15} />{t('account.sessions.thisDevice')}</span>
                ) : (
                  <button
                    aria-label={t('account.sessions.revokeAria', { device: session.device })}
                    onClick={() => revokeSession(session.id)}
                    type="button"
                  >
                    {t('account.sessions.revoke')}
                  </button>
                )}
              </footer>
            </article>
          )
        })}
      </section>

      <section className="account-wide-note">
        <ShieldCheck size={19} />
        <div><strong>{t('account.sessions.securityTitle')}</strong><p>{t('account.sessions.securityDescription')}</p></div>
      </section>

      {notice && <div className="account-toast" role="status"><CircleCheck size={17} />{notice}</div>}
    </AccountShell>
  )
}
