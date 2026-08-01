import { useMemo, useState } from 'react'
import { CalendarDays, Download, Filter, Search, ShieldCheck } from 'lucide-react'
import { PageHeader, StatusPill } from '../../components/ui'
import { auditEvents, type AuditCategory } from '../../data/mock'
import { useI18n } from '../../i18n'
import { AUDIT_ACTION_KEYS, AUDIT_CATEGORY_KEYS, RESULT_STATUS_KEYS } from '../../i18n/domain'

function resultTone(result: string) {
  if (result === 'success') return 'success' as const
  if (result === 'warning') return 'warning' as const
  return 'danger' as const
}

export function AuditPage() {
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<'all' | AuditCategory>('all')
  const { formatDate, formatNumber, t } = useI18n()

  const filteredEvents = useMemo(() => {
    const normalized = query.toLowerCase().trim()
    return auditEvents.filter((event) => {
      const matchesCategory = category === 'all' || event.category === category
      const searchableText = `${t(AUDIT_ACTION_KEYS[event.action])} ${t(AUDIT_CATEGORY_KEYS[event.category])} ${event.actor} ${event.target} ${event.id}`
      const matchesQuery = !normalized || searchableText.toLowerCase().includes(normalized)
      return matchesCategory && matchesQuery
    })
  }, [category, query, t])

  return (
    <>
      <PageHeader
        eyebrow={t('audit.eyebrow')}
        title={t('audit.title')}
        description={t('audit.description')}
        actions={
          <>
            <button className="button button--secondary" type="button"><CalendarDays size={16} />{t('audit.lastThirtyDays')}</button>
            <button className="button button--secondary" type="button"><Download size={16} />{t('audit.exportCsv')}</button>
          </>
        }
      />

      <div className="audit-retention"><ShieldCheck size={17} /><span><strong>{t('audit.integrityTitle')}</strong> {t('audit.integrityDescription')}</span></div>

      <section className="panel directory-panel">
        <div className="directory-toolbar">
          <label className="table-search table-search--wide"><Search size={16} /><input aria-label={t('audit.searchPlaceholder')} name="audit-search" onChange={(event) => setQuery(event.target.value)} placeholder={t('audit.searchPlaceholder')} value={query} /></label>
          <label className="select-shell"><Filter size={15} /><select aria-label={t('audit.filterAria')} onChange={(event) => setCategory(event.target.value as 'all' | AuditCategory)} value={category}><option value="all">{t('audit.category.all')}</option><option value="authentication">{t('audit.category.authentication')}</option><option value="user">{t('audit.category.user')}</option><option value="application">{t('audit.category.application')}</option><option value="security">{t('audit.category.security')}</option></select></label>
        </div>
        <div className="table-scroll">
          <table className="data-table audit-table">
            <thead><tr><th>{t('audit.event')}</th><th>{t('audit.category')}</th><th>{t('audit.actor')}</th><th>{t('audit.target')}</th><th>{t('audit.ipAddress')}</th><th>{t('audit.time')}</th><th>{t('audit.result')}</th></tr></thead>
            <tbody>
              {filteredEvents.map((event) => (
                <tr key={event.id}>
                  <td><div className="event-cell"><span className={`event-cell__icon event-cell__icon--${event.result}`}><ShieldCheck size={16} /></span><span><strong>{t(AUDIT_ACTION_KEYS[event.action])}</strong><small>{event.id}</small></span></div></td>
                  <td><span className="category-tag">{t(AUDIT_CATEGORY_KEYS[event.category])}</span></td>
                  <td>{event.actor === 'System' ? t('common.system') : event.actor}</td>
                  <td className="muted-cell">{event.target}</td>
                  <td><code className="inline-code">{event.ip}</code></td>
                  <td className="muted-cell audit-time">{formatDate(event.time, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</td>
                  <td><StatusPill tone={resultTone(event.result)}>{t(RESULT_STATUS_KEYS[event.result])}</StatusPill></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <footer className="table-footer"><span>{t('audit.showing', { count: formatNumber(filteredEvents.length) })}</span><div className="pagination"><button disabled type="button">{t('common.previous')}</button><button className="is-active" type="button">1</button><button type="button">2</button><button type="button">{t('common.next')}</button></div></footer>
      </section>
    </>
  )
}
