import { ArrowLeft, ArrowRight, AtSign, ShieldCheck, UserRound } from 'lucide-react'
import { useNavigate } from '../../router-context'
import { AuthLayout } from '../../components/AuthLayout'
import { useI18n } from '../../i18n'

export function ConsentPage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const permissions = [
    { icon: UserRound, title: t('consent.profileTitle'), description: t('consent.profileDescription') },
    { icon: AtSign, title: t('consent.emailTitle'), description: t('consent.emailDescription') },
    { icon: ShieldCheck, title: t('consent.identityTitle'), description: t('consent.identityDescription') },
  ]

  return (
    <AuthLayout
      eyebrow={t('consent.eyebrow')}
      title={t('consent.heroTitle')}
      description={t('consent.heroDescription')}
    >
      <header className="consent-heading">
        <div className="consent-app-mark">A</div>
        <h2>{t('consent.title')}</h2>
        <p>{t('consent.description')}</p>
      </header>

      <div className="signed-in-as">
        <span className="signed-in-as__avatar">MC</span>
        <span>
          <small>{t('consent.signedInAs')}</small>
          <strong>Maya Chen</strong>
        </span>
        <button onClick={() => navigate('/login')} type="button">{t('consent.switch')}</button>
      </div>

      <div className="permission-list">
        <span className="permission-list__label">{t('consent.allowIntro')}</span>
        {permissions.map(({ icon: Icon, title, description }) => (
          <div className="permission-item" key={title}>
            <span className="permission-item__icon"><Icon size={18} /></span>
            <span><strong>{title}</strong><small>{description}</small></span>
            <span className="permission-item__check"><ShieldCheck size={17} /></span>
          </div>
        ))}
      </div>

      <div className="consent-actions">
        <button className="button button--secondary" onClick={() => navigate('/login')} type="button">
          <ArrowLeft size={16} /> {t('consent.cancel')}
        </button>
        <button className="button button--primary" onClick={() => navigate('/complete')} type="button">
          {t('consent.allow')} <ArrowRight size={16} />
        </button>
      </div>

      <p className="consent-legal">
        {t('consent.legalPrefix')} <a href="#privacy">{t('consent.privacy')}</a> {t('consent.legalAnd')}{' '}
        <a href="#terms">{t('consent.terms')}</a>{t('common.sentenceEnd')}
      </p>
    </AuthLayout>
  )
}
