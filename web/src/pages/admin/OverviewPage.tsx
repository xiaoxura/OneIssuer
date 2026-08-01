import {
  AppWindow,
  ArrowRight,
  CalendarDays,
  CheckCircle2,
  Database,
  KeyRound,
  LogIn,
  MoreHorizontal,
  Plus,
  Radio,
  ShieldCheck,
  UsersRound,
} from 'lucide-react'
import { Link } from '../../router'
import { applications, recentSignIns, signInSeries } from '../../data/mock'
import { Avatar, MetricCard, PageHeader, StatusPill } from '../../components/ui'
import { useI18n } from '../../i18n'
import { APPLICATION_TYPE_KEYS, LOCATION_KEYS, RESULT_STATUS_KEYS } from '../../i18n/domain'

function SignInChart() {
  const { formatDate, t } = useI18n()
  const width = 700
  const height = 230
  const padX = 24
  const padTop = 18
  const chartHeight = 160
  const max = 700
  const step = (width - padX * 2) / (signInSeries.length - 1)
  const coordinates = signInSeries.map((item, index) => ({
    x: padX + index * step,
    y: padTop + chartHeight - (item.success / max) * chartHeight,
  }))
  const line = coordinates.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ')
  const area = `${line} L ${coordinates.at(-1)?.x ?? width - padX} ${padTop + chartHeight} L ${padX} ${padTop + chartHeight} Z`

  return (
    <div className="signin-chart">
      <svg aria-label={t('overview.chartLabel')} role="img" viewBox={`0 0 ${width} ${height}`}>
        <defs>
          <linearGradient id="signin-area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#a1a1aa" stopOpacity="0.24" />
            <stop offset="100%" stopColor="#a1a1aa" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 1, 2, 3].map((lineIndex) => {
          const y = padTop + (chartHeight / 3) * lineIndex
          return <line className="chart-grid-line" key={lineIndex} x1={padX} x2={width - padX} y1={y} y2={y} />
        })}
        <path d={area} fill="url(#signin-area)" />
        <path className="chart-main-line" d={line} fill="none" />
        {coordinates.map((point, index) => (
          <g key={signInSeries[index].date}>
            <circle className="chart-dot-halo" cx={point.x} cy={point.y} r="8" />
            <circle className="chart-dot" cx={point.x} cy={point.y} r="3.5" />
            <text className="chart-day" textAnchor="middle" x={point.x} y={height - 18}>
              {formatDate(signInSeries[index].date, { weekday: 'short' })}
            </text>
          </g>
        ))}
      </svg>
    </div>
  )
}

export function OverviewPage() {
  const { formatDate, formatNumber, formatRelativeTime, t } = useI18n()

  return (
    <>
      <PageHeader
        eyebrow={formatDate('2026-07-31T12:00:00Z', { weekday: 'long', month: 'long', day: 'numeric', timeZone: 'UTC' })}
        title={t('overview.title')}
        description={t('overview.description')}
        actions={
          <>
            <button className="button button--secondary" type="button">
              <CalendarDays size={16} /> {t('overview.lastSevenDays')}
            </button>
            <Link className="button button--primary" to="/admin/applications/new">
              <Plus size={17} /> {t('overview.addApplication')}
            </Link>
          </>
        }
      />

      <section className="metrics-grid" aria-label={t('overview.metrics')}>
        <MetricCard label={t('overview.activeUsers')} value={formatNumber(1284)} change="12.4%" icon={UsersRound} detail={t('overview.vsLastPeriod')} />
        <MetricCard label={t('overview.applications')} value={formatNumber(8)} change={t('overview.newCount', { count: formatNumber(2) })} icon={AppWindow} detail={t('overview.thisMonth')} />
        <MetricCard label={t('overview.signIns24h')} value={formatNumber(3892)} change="8.7%" icon={LogIn} detail={t('overview.vsYesterday')} />
        <MetricCard label={t('overview.mfaCoverage')} value="76%" change="8.2%" icon={ShieldCheck} detail={t('overview.ofActiveUsers')} />
      </section>

      <section className="overview-grid">
        <article className="panel panel--chart">
          <header className="panel__header">
            <div>
              <span className="panel__eyebrow">{t('overview.authentication')}</span>
              <h2>{t('overview.signInActivity')}</h2>
            </div>
            <div className="chart-summary">
              <span><i className="legend-dot legend-dot--success" />{t('overview.successful')} <strong>{formatNumber(3037)}</strong></span>
              <span><i className="legend-dot legend-dot--failed" />{t('overview.failed')} <strong>{formatNumber(236)}</strong></span>
            </div>
          </header>
          <SignInChart />
        </article>

        <article className="panel health-panel">
          <header className="panel__header">
            <div>
              <span className="panel__eyebrow">{t('overview.infrastructure')}</span>
              <h2>{t('overview.systemHealth')}</h2>
            </div>
            <StatusPill tone="success">{t('overview.healthy')}</StatusPill>
          </header>
          <div className="health-score">
            <div className="health-score__ring"><strong>99.99</strong><small>{t('overview.uptime')}</small></div>
            <p>{t('overview.servicesNormal')}</p>
          </div>
          <div className="service-list">
            <div><span><Radio size={16} />{t('overview.issuerEndpoints')}</span><strong>42 ms</strong></div>
            <div><span><Database size={16} />PostgreSQL</span><strong>8 ms</strong></div>
            <div><span><KeyRound size={16} />{t('overview.signingKeys')}</span><strong>{t('common.active')}</strong></div>
          </div>
        </article>
      </section>

      <section className="overview-bottom-grid">
        <article className="panel recent-panel">
          <header className="panel__header">
            <div>
              <span className="panel__eyebrow">{t('overview.liveActivity')}</span>
              <h2>{t('overview.recentSignIns')}</h2>
            </div>
            <Link className="panel-link" to="/admin/audit">{t('overview.viewAuditLog')} <ArrowRight size={14} /></Link>
          </header>
          <div className="table-scroll">
            <table className="data-table data-table--compact">
              <thead><tr><th>{t('overview.user')}</th><th>{t('overview.application')}</th><th>{t('overview.location')}</th><th>{t('overview.time')}</th><th>{t('overview.result')}</th><th><span className="sr-only">{t('common.actions')}</span></th></tr></thead>
              <tbody>
                {recentSignIns.map(({ user, application, location, time, result }) => (
                  <tr key={`${user.id}-${time}`}>
                    <td><div className="user-cell"><Avatar initials={user.initials} tone={user.tone} size="small" /><span><strong>{user.name}</strong><small>{user.email}</small></span></div></td>
                    <td>{application}</td>
                    <td className="muted-cell">{t(LOCATION_KEYS[location])}</td>
                    <td className="muted-cell">{formatRelativeTime(time.value, time.unit)}</td>
                    <td><StatusPill tone={result === 'success' ? 'success' : 'danger'}>{t(RESULT_STATUS_KEYS[result])}</StatusPill></td>
                    <td><button className="table-action" type="button" aria-label={t('overview.moreActions', { name: user.name })}><MoreHorizontal size={17} /></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <article className="panel application-usage">
          <header className="panel__header">
            <div>
              <span className="panel__eyebrow">{t('overview.applications')}</span>
              <h2>{t('overview.mostActive')}</h2>
            </div>
            <Link className="panel-link" to="/admin/applications">{t('overview.viewAll')}</Link>
          </header>
          <div className="application-usage__list">
            {applications.slice(0, 3).map((application, index) => (
              <div key={application.id}>
                <span className={`app-mini app-mini--${application.tone}`}>{application.initials}</span>
                <span><strong>{application.name}</strong><small>{t(APPLICATION_TYPE_KEYS[application.type])}</small></span>
                <span className="usage-rank"><small>{t('overview.signIns')}</small><strong>{formatNumber(application.signIns, { notation: 'compact', maximumFractionDigits: 1 })}</strong></span>
                {index === 0 && <CheckCircle2 className="usage-leader" size={15} />}
              </div>
            ))}
          </div>
        </article>
      </section>
    </>
  )
}
