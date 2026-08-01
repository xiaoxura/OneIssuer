import { AppWindow, Code2, Copy, ExternalLink, Globe2, MoreHorizontal, Plus, Search, Terminal } from 'lucide-react'
import { Link } from '../../router'
import { PageHeader, StatusPill } from '../../components/ui'
import { applications } from '../../data/mock'
import { useI18n } from '../../i18n'
import { APPLICATION_STATUS_KEYS, APPLICATION_TYPE_KEYS } from '../../i18n/domain'

function applicationIcon(type: string) {
  if (type === 'spa') return Code2
  if (type === 'native') return Terminal
  return Globe2
}

export function ApplicationsPage() {
  const { formatNumber, formatRelativeTime, t } = useI18n()

  return (
    <>
      <PageHeader
        eyebrow={t('applications.eyebrow')}
        title={t('applications.title')}
        description={t('applications.description')}
        actions={
          <Link className="button button--primary" to="/admin/applications/new">
            <Plus size={17} /> {t('applications.new')}
          </Link>
        }
      />

      <div className="applications-toolbar">
        <label className="table-search table-search--wide"><Search size={16} /><input aria-label={t('applications.searchPlaceholder')} name="application-search" placeholder={t('applications.searchPlaceholder')} /></label>
        <div className="segmented-control" role="group" aria-label={t('applications.filterAria')}>
          <button className="is-active" type="button">{t('common.all')} <span>8</span></button>
          <button type="button">{t('common.production')} <span>6</span></button>
          <button type="button">{t('common.development')} <span>2</span></button>
        </div>
      </div>

      <section className="application-grid">
        {applications.map((application) => {
          const TypeIcon = applicationIcon(application.type)
          return (
            <article className="application-card" key={application.id}>
              <header className="application-card__header">
                <span className={`application-mark application-mark--${application.tone}`}>{application.initials}</span>
                <div><h2>{application.name}</h2><span><TypeIcon size={14} />{t(APPLICATION_TYPE_KEYS[application.type])}</span></div>
                <button className="table-action" type="button" aria-label={t('applications.moreActions', { name: application.name })}><MoreHorizontal size={18} /></button>
              </header>

              <div className="application-card__status">
                <StatusPill tone={application.status === 'live' ? 'success' : 'warning'}>{t(APPLICATION_STATUS_KEYS[application.status])}</StatusPill>
                <span>{t('applications.updated', { time: formatRelativeTime(application.updated.value, application.updated.unit) })}</span>
              </div>

              <div className="application-card__meta">
                <div><span>{t('applications.clientId')}</span><code>{application.clientId}</code><button type="button" aria-label={t('applications.copyClientId')}><Copy size={13} /></button></div>
                <div><span>{t('applications.redirectUri')}</span><code>{application.redirectUri}</code><button type="button" aria-label={t('applications.openRedirectUri')}><ExternalLink size={13} /></button></div>
              </div>

              <footer className="application-card__footer">
                <span>{t('applications.monthlySignIns', { count: formatNumber(application.signIns, { notation: 'compact', maximumFractionDigits: 1 }) })}</span>
                <button type="button">{t('applications.viewConfiguration')} <ExternalLink size={14} /></button>
              </footer>
            </article>
          )
        })}

        <Link className="application-card application-card--new" to="/admin/applications/new">
          <span><AppWindow size={24} /></span>
          <strong>{t('applications.connectAnother')}</strong>
          <small>{t('applications.configureClient')}</small>
        </Link>
      </section>
    </>
  )
}
