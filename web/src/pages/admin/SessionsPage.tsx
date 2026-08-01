import { useState } from 'react'
import { Clock3, Laptop, LogOut, MapPin, MoreHorizontal, RefreshCw, Search, ShieldX, Smartphone } from 'lucide-react'
import { Avatar, PageHeader, StatusPill } from '../../components/ui'
import { initialSessions } from '../../data/mock'
import { useI18n } from '../../i18n'
import { LOCATION_KEYS } from '../../i18n/domain'

function DeviceIcon({ device }: { device: string }) {
  if (device.includes('iPhone') || device.includes('Pixel')) return <Smartphone size={19} />
  return <Laptop size={19} />
}

export function SessionsPage() {
  const [sessions, setSessions] = useState(initialSessions)
  const { formatDate, formatNumber, formatRelativeTime, t } = useI18n()

  return (
    <>
      <PageHeader
        eyebrow={t('sessions.eyebrow')}
        title={t('sessions.title')}
        description={t('sessions.description')}
        actions={
          <button className="button button--danger-soft" onClick={() => setSessions((current) => current.filter((session) => session.current))} type="button">
            <ShieldX size={17} /> {t('sessions.revokeOthers')}
          </button>
        }
      />

      <section className="session-summary-grid">
        <article><span><Clock3 size={18} /></span><div><strong>{formatNumber(sessions.length)}</strong><small>{t('sessions.activeSessions')}</small></div></article>
        <article><span><RefreshCw size={18} /></span><div><strong>12</strong><small>{t('sessions.refreshFamilies')}</small></div></article>
        <article><span><MapPin size={18} /></span><div><strong>4</strong><small>{t('sessions.locationsWeek')}</small></div></article>
      </section>

      <section className="panel directory-panel">
        <div className="directory-toolbar">
          <label className="table-search"><Search size={16} /><input aria-label={t('sessions.searchPlaceholder')} name="session-search" placeholder={t('sessions.searchPlaceholder')} /></label>
          <div className="session-legend"><i />{t('sessions.expiryNotice')}</div>
        </div>
        <div className="table-scroll">
          <table className="data-table sessions-table">
            <thead><tr><th>{t('sessions.user')}</th><th>{t('sessions.device')}</th><th>{t('sessions.location')}</th><th>{t('sessions.created')}</th><th>{t('sessions.lastActive')}</th><th>{t('sessions.status')}</th><th><span className="sr-only">{t('common.actions')}</span></th></tr></thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={session.id}>
                  <td><div className="user-cell"><Avatar initials={session.user.initials} tone={session.user.tone} size="small" /><span><strong>{session.user.name}</strong><small>{session.user.email}</small></span></div></td>
                  <td><div className="device-cell"><span><DeviceIcon device={session.device} /></span><div><strong>{session.device}</strong><small>{session.browser}</small></div></div></td>
                  <td><span className="location-cell"><MapPin size={14} />{t(LOCATION_KEYS[session.location])}<small>{session.ip}</small></span></td>
                  <td className="muted-cell">{formatDate(session.created, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</td>
                  <td className="muted-cell">{formatRelativeTime(session.lastActive.value, session.lastActive.unit)}</td>
                  <td>{session.current ? <StatusPill tone="success">{t('common.current')}</StatusPill> : <StatusPill tone="neutral">{t('common.active')}</StatusPill>}</td>
                  <td>
                    {session.current ? (
                      <button className="table-action" type="button" aria-label={t('sessions.moreActions')}><MoreHorizontal size={18} /></button>
                    ) : (
                      <button className="revoke-button" onClick={() => setSessions((current) => current.filter((item) => item.id !== session.id))} type="button"><LogOut size={14} />{t('sessions.revoke')}</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <footer className="table-footer"><span>{t('sessions.showing', { count: formatNumber(sessions.length) })}</span><span className="table-footer__hint">{t('sessions.digestHint')}</span></footer>
      </section>
    </>
  )
}
