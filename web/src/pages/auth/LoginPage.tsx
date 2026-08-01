import { useState, type FormEvent } from 'react'
import { ArrowRight, Eye, EyeOff, GitFork, KeyRound, LockKeyhole, Mail } from 'lucide-react'
import { Link } from '../../router'
import { useNavigate } from '../../router-context'
import { AuthLayout } from '../../components/AuthLayout'
import { useI18n } from '../../i18n'

export function LoginPage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [showPassword, setShowPassword] = useState(false)

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    navigate('/consent')
  }

  return (
    <AuthLayout
      eyebrow={t('login.eyebrow')}
      title={t('login.heroTitle')}
      description={t('login.heroDescription')}
    >
      <header className="auth-card__heading">
        <span className="auth-card__kicker">{t('login.kicker')}</span>
        <h2>{t('login.title')}</h2>
        <p>{t('login.description')}</p>
      </header>

      <button className="social-button" type="button">
        <GitFork size={18} />
        {t('login.github')}
      </button>

      <div className="form-divider">
        <span>{t('login.emailDivider')}</span>
      </div>

      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="form-field">
          <span>{t('login.email')}</span>
          <span className="input-shell">
            <Mail size={17} />
            <input autoComplete="email" defaultValue="maya@acme.dev" required type="email" />
          </span>
        </label>

        <label className="form-field">
          <span className="form-field__row">
            <span>{t('login.password')}</span>
            <a href="#forgot">{t('login.forgotPassword')}</a>
          </span>
          <span className="input-shell">
            <LockKeyhole size={17} />
            <input
              autoComplete="current-password"
              defaultValue="oneissuer-demo"
              minLength={8}
              required
              type={showPassword ? 'text' : 'password'}
            />
            <button
              className="input-action"
              type="button"
              onClick={() => setShowPassword((value) => !value)}
              aria-label={showPassword ? t('login.hidePassword') : t('login.showPassword')}
            >
              {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
            </button>
          </span>
        </label>

        <label className="checkbox-row">
          <input defaultChecked type="checkbox" />
          <span>{t('login.keepSignedIn')}</span>
        </label>

        <button className="button button--primary button--full" type="submit">
          {t('login.continue')}
          <ArrowRight size={17} />
        </button>
      </form>

      <p className="auth-card__switch">
        {t('login.newUser')} <Link to="/register">{t('login.createAccount')}</Link>
      </p>

      <div className="auth-security-note">
        <KeyRound size={16} />
        <span>{t('login.securityNote')}</span>
      </div>
    </AuthLayout>
  )
}
