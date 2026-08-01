import { useState } from 'react'
import {
  Check,
  ChevronRight,
  CircleCheck,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  MailCheck,
  Plus,
  ShieldCheck,
} from 'lucide-react'
import { AccountShell } from '../../components/AccountShell'
import { StatusPill } from '../../components/ui'
import { useI18n } from '../../i18n'

export function AccountSecurityPage() {
  const { t } = useI18n()
  const [passkeyCount, setPasskeyCount] = useState(1)
  const [notice, setNotice] = useState<string | null>(null)

  function addPasskey() {
    setPasskeyCount(2)
    setNotice(t('account.security.passkeyAdded'))
    window.setTimeout(() => setNotice(null), 2200)
  }

  const recommendations = [
    { title: t('account.security.recommendation.passkey'), detail: t('account.security.recommendation.passkeyDetail'), complete: passkeyCount > 1 },
    { title: t('account.security.recommendation.recovery'), detail: t('account.security.recommendation.recoveryDetail'), complete: true },
    { title: t('account.security.recommendation.email'), detail: 'alex@oneissuer.dev', complete: true },
  ]

  return (
    <AccountShell name="Alex Lin">
      <header className="account-route-header">
        <div>
          <span className="account-eyebrow">{t('account.security.eyebrow')}</span>
          <h1>{t('account.security.title')}</h1>
          <p>{t('account.security.pageDescription')}</p>
        </div>
        <StatusPill tone="success">{t('account.security.strong')}</StatusPill>
      </header>

      <div className="account-detail-layout">
        <section className="account-panel account-security-panel">
          <header className="account-panel__header">
            <div>
              <span className="account-panel__eyebrow">{t('account.security.scoreEyebrow')}</span>
              <h2>{t('account.security.scoreTitle')}</h2>
              <p>{t('account.security.description')}</p>
            </div>
          </header>

          <div className="account-security-summary">
            <div className="account-security-score" role="img" aria-label={t('account.security.scoreAria')}>
              <strong>86</strong>
              <span>/ 100</span>
            </div>
            <div className="account-security-progress">
              <strong>{t('account.security.progressTitle')}</strong>
              <p>{t('account.security.progressDescription')}</p>
              <div aria-hidden="true"><span /></div>
            </div>
            <button className="button button--primary" onClick={addPasskey} type="button">
              <Plus size={16} /> {t('account.security.addPasskey')}
            </button>
          </div>

          <div className="account-method-list account-method-list--roomy">
            <article>
              <span className="account-method-list__icon"><LockKeyhole size={19} /></span>
              <span><strong>{t('account.security.password')}</strong><small>{t('account.security.passwordDescription')}</small></span>
              <button type="button">{t('account.security.change')}</button>
            </article>
            <article>
              <span className="account-method-list__icon"><Fingerprint size={19} /></span>
              <span><strong>{t('account.security.passkeys')}</strong><small>{t('account.security.passkeyDescription', { count: passkeyCount })}</small></span>
              <button type="button">{t('account.security.manage')}</button>
            </article>
            <article>
              <span className="account-method-list__icon"><KeyRound size={19} /></span>
              <span><strong>{t('account.security.authenticator')}</strong><small>{t('account.security.authenticatorDescription')}</small></span>
              <StatusPill tone="success">{t('common.enabled')}</StatusPill>
            </article>
            <article>
              <span className="account-method-list__icon"><MailCheck size={19} /></span>
              <span><strong>{t('account.security.recovery')}</strong><small>{t('account.security.recoveryDescription')}</small></span>
              <button type="button">{t('account.security.viewCodes')}</button>
            </article>
          </div>
        </section>

        <aside className="account-side-panel">
          <header>
            <span><ShieldCheck size={19} /></span>
            <div><h2>{t('account.security.recommendationsTitle')}</h2><p>{t('account.security.recommendationsDescription')}</p></div>
          </header>
          <div className="account-recommendation-list">
            {recommendations.map((item) => (
              <article key={item.title}>
                <span className={item.complete ? 'is-complete' : ''}>{item.complete ? <Check size={15} /> : <ChevronRight size={15} />}</span>
                <div><strong>{item.title}</strong><small>{item.detail}</small></div>
              </article>
            ))}
          </div>
          <div className="account-side-note">
            <LockKeyhole size={16} />
            <span><strong>{t('account.security.reauthTitle')}</strong><small>{t('account.security.reauthDescription')}</small></span>
          </div>
        </aside>
      </div>

      {notice && <div className="account-toast" role="status"><CircleCheck size={17} />{notice}</div>}
    </AccountShell>
  )
}
