import { ArrowRight, CircleCheck, LayoutDashboard, ShieldCheck } from 'lucide-react'
import { Link } from '../../router'
import { AuthLayout } from '../../components/AuthLayout'
import { useI18n } from '../../i18n'

export function CompletePage() {
  const { t } = useI18n()

  return (
    <AuthLayout
      eyebrow={t('complete.eyebrow')}
      title={t('complete.heroTitle')}
      description={t('complete.heroDescription')}
    >
      <div className="complete-state">
        <span className="complete-state__icon"><CircleCheck size={34} /></span>
        <span className="auth-card__kicker">{t('complete.kicker')}</span>
        <h2>{t('complete.title')}</h2>
        <p>{t('complete.description')}</p>

        <div className="complete-route">
          <span className="complete-route__app">A</span>
          <span className="complete-route__line"><i /></span>
          <span className="complete-route__issuer"><ShieldCheck size={20} /></span>
        </div>

        <Link className="button button--primary button--full" to="/admin">
          {t('complete.openAdmin')} <LayoutDashboard size={17} />
        </Link>
        <Link className="text-link" to="/login">
          {t('complete.returnToSignIn')} <ArrowRight size={14} />
        </Link>
      </div>
    </AuthLayout>
  )
}
