import type { ReactNode } from 'react'
import { AppWindow, Braces, Fingerprint, ShieldCheck } from 'lucide-react'
import { Link } from '../router'
import { useLocation } from '../router-context'
import { useI18n, type TranslationKey } from '../i18n'
import { Brand } from './Brand'
import { LanguageSwitcher } from './LanguageSwitcher'

type AuthLayoutProps = {
  children: ReactNode
  eyebrow: string
  title: string
  description: string
  clientName?: string
}

const previewRoutes = [
  { labelKey: 'auth.layout.signIn', path: '/login' },
  { labelKey: 'auth.layout.createAccount', path: '/register' },
  { labelKey: 'auth.layout.consent', path: '/consent' },
  { labelKey: 'auth.layout.accountCenter', path: '/account' },
] satisfies Array<{ labelKey: TranslationKey; path: string }>

export function AuthLayout({
  children,
  eyebrow,
  title,
  description,
  clientName = 'Acme Workspace',
}: AuthLayoutProps) {
  const location = useLocation()
  const { t } = useI18n()

  return (
    <main className="auth-layout">
      <section className="auth-visual" aria-label={t('auth.layout.introduction')}>
        <div className="auth-visual__grid" aria-hidden="true" />
        <header className="auth-visual__header">
          <Brand />
          <div className="auth-visual__tools">
            <span className="auth-visual__edition">{t('auth.layout.communityPreview')}</span>
            <LanguageSwitcher />
          </div>
        </header>

        <div className="auth-visual__content">
          <div className="eyebrow eyebrow--dark">{eyebrow}</div>
          <h1>{title}</h1>
          <p>{description}</p>

          <div className="identity-orbit" aria-hidden="true">
            <div className="identity-orbit__ring identity-orbit__ring--outer" />
            <div className="identity-orbit__ring identity-orbit__ring--inner" />
            <div className="identity-orbit__core">
              <Fingerprint size={29} strokeWidth={1.8} />
            </div>
            <div className="identity-orbit__node identity-orbit__node--one">
              <AppWindow size={17} />
            </div>
            <div className="identity-orbit__node identity-orbit__node--two">
              <Braces size={17} />
            </div>
            <div className="identity-orbit__node identity-orbit__node--three">
              <ShieldCheck size={17} />
            </div>
            <span className="identity-orbit__signal identity-orbit__signal--one" />
            <span className="identity-orbit__signal identity-orbit__signal--two" />
          </div>
        </div>

        <footer className="auth-visual__footer">
          <ShieldCheck size={17} />
          <span>{t('auth.layout.trustedIdentity')}</span>
        </footer>
      </section>

      <section className="auth-workspace">
        <header className="auth-workspace__mobile-header">
          <Brand />
          <div className="auth-workspace__mobile-tools">
            <LanguageSwitcher />
            <span className="prototype-chip">{t('auth.layout.prototype')}</span>
          </div>
        </header>

        <div className="auth-workspace__center">
          <div className="client-context">
            <span className="client-context__logo">A</span>
            <span>
              {t('auth.layout.continueTo', { client: clientName })}
            </span>
          </div>
          <div className="auth-card">{children}</div>
        </div>

        <footer className="auth-workspace__footer">
          <nav className="prototype-nav" aria-label={t('auth.layout.prototypeNav')}>
            <span>{t('auth.layout.prototype')}</span>
            {previewRoutes.map((route) => (
              <Link
                className={location.pathname === route.path ? 'is-active' : ''}
                key={route.path}
                to={route.path}
              >
                {t(route.labelKey)}
              </Link>
            ))}
            <Link to="/admin">{t('auth.layout.adminConsole')}</Link>
          </nav>
          <span className="auth-workspace__legal">{t('auth.layout.legal')}</span>
        </footer>
      </section>
    </main>
  )
}
