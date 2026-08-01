import { useMemo, useState, type FormEvent } from 'react'
import { ArrowRight, Check, Eye, EyeOff, LockKeyhole, Mail, UserRound } from 'lucide-react'
import { Link } from '../../router'
import { useNavigate } from '../../router-context'
import { AuthLayout } from '../../components/AuthLayout'
import { useI18n, type TranslationKey } from '../../i18n'

export function RegisterPage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [accepted, setAccepted] = useState(false)

  const passwordChecks = useMemo(
    () => [
      { labelKey: 'register.passwordLength', passed: password.length >= 8 },
      { labelKey: 'register.passwordCase', passed: /[a-z]/.test(password) && /[A-Z]/.test(password) },
      { labelKey: 'register.passwordNumber', passed: /\d/.test(password) },
    ],
    [password],
  ) satisfies Array<{ labelKey: TranslationKey; passed: boolean }>

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    navigate('/consent')
  }

  return (
    <AuthLayout
      eyebrow={t('register.eyebrow')}
      title={t('register.heroTitle')}
      description={t('register.heroDescription')}
    >
      <header className="auth-card__heading">
        <span className="auth-card__kicker">{t('register.kicker')}</span>
        <h2>{t('register.title')}</h2>
        <p>{t('register.description')}</p>
      </header>

      <div className="register-progress" aria-label={t('register.progress')}>
        <span className="is-active"><i>1</i> {t('register.accountStep')}</span>
        <span className="register-progress__line" />
        <span><i>2</i> {t('register.verifyStep')}</span>
      </div>

      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="form-field">
          <span>{t('register.fullName')}</span>
          <span className="input-shell">
            <UserRound size={17} />
            <input autoComplete="name" placeholder="Maya Chen" required />
          </span>
        </label>

        <label className="form-field">
          <span>{t('register.email')}</span>
          <span className="input-shell">
            <Mail size={17} />
            <input autoComplete="email" placeholder="you@company.com" required type="email" />
          </span>
        </label>

        <label className="form-field">
          <span>{t('register.password')}</span>
          <span className="input-shell">
            <LockKeyhole size={17} />
            <input
              autoComplete="new-password"
              minLength={8}
              onChange={(event) => setPassword(event.target.value)}
              placeholder={t('register.passwordPlaceholder')}
              required
              type={showPassword ? 'text' : 'password'}
              value={password}
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

        <div className="password-checks" aria-live="polite">
          {passwordChecks.map((check) => (
            <span className={check.passed ? 'is-passed' : ''} key={check.labelKey}>
              <Check size={13} /> {t(check.labelKey)}
            </span>
          ))}
        </div>

        <label className="checkbox-row checkbox-row--terms">
          <input checked={accepted} onChange={(event) => setAccepted(event.target.checked)} type="checkbox" />
          <span>
            {t('register.agreePrefix')} <a href="#terms">{t('register.terms')}</a> {t('register.and')} <a href="#privacy">{t('register.privacy')}</a>{t('common.sentenceEnd')}
          </span>
        </label>

        <button className="button button--primary button--full" disabled={!accepted} type="submit">
          {t('register.create')}
          <ArrowRight size={17} />
        </button>
      </form>

      <p className="auth-card__switch">
        {t('register.existingUser')} <Link to="/login">{t('register.signIn')}</Link>
      </p>
    </AuthLayout>
  )
}
