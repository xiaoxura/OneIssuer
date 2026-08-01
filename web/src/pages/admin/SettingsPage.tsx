import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import {
  Check,
  Copy,
  ExternalLink,
  Fingerprint,
  Globe2,
  KeyRound,
  LockKeyhole,
  RefreshCw,
  Save,
  ShieldCheck,
  UserPlus,
} from 'lucide-react'
import { PageHeader, StatusPill } from '../../components/ui'
import { NavLink } from '../../router'
import { useLocation } from '../../router-context'
import { useI18n, type TranslationKey } from '../../i18n'

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: () => void; label: string }) {
  return (
    <button aria-checked={checked} aria-label={label} className={`toggle ${checked ? 'is-on' : ''}`} onClick={onChange} role="switch" type="button">
      <span />
    </button>
  )
}

type SettingsSection = 'issuer' | 'registration' | 'authentication' | 'tokens' | 'keys'

const settingsNavigation: Array<{
  id: SettingsSection
  path: string
  labelKey: TranslationKey
  icon: typeof Globe2
  end?: boolean
}> = [
  { id: 'issuer', path: '/admin/settings', labelKey: 'settings.nav.issuer', icon: Globe2, end: true },
  { id: 'registration', path: '/admin/settings/registration', labelKey: 'settings.nav.registration', icon: UserPlus },
  { id: 'authentication', path: '/admin/settings/authentication', labelKey: 'settings.nav.authentication', icon: Fingerprint },
  { id: 'tokens', path: '/admin/settings/tokens', labelKey: 'settings.nav.tokens', icon: RefreshCw },
  { id: 'keys', path: '/admin/settings/keys', labelKey: 'settings.nav.keys', icon: KeyRound },
]

const sectionMeta: Record<SettingsSection, { titleKey: TranslationKey; descriptionKey: TranslationKey }> = {
  issuer: { titleKey: 'settings.issuer.title', descriptionKey: 'settings.issuer.description' },
  registration: { titleKey: 'settings.registration.title', descriptionKey: 'settings.registration.description' },
  authentication: { titleKey: 'settings.authentication.title', descriptionKey: 'settings.authentication.description' },
  tokens: { titleKey: 'settings.tokens.title', descriptionKey: 'settings.tokens.description' },
  keys: { titleKey: 'settings.keys.title', descriptionKey: 'settings.keys.description' },
}

export function SettingsPage() {
  const { pathname } = useLocation()
  const { formatDate, t } = useI18n()
  const settingsNavRef = useRef<HTMLElement>(null)
  const [registrationEnabled, setRegistrationEnabled] = useState(true)
  const [githubEnabled, setGithubEnabled] = useState(true)
  const [passkeysEnabled, setPasskeysEnabled] = useState(false)
  const [saved, setSaved] = useState(false)
  const [copied, setCopied] = useState(false)

  const activeSection: SettingsSection = pathname.endsWith('/registration')
    ? 'registration'
    : pathname.endsWith('/authentication')
      ? 'authentication'
      : pathname.endsWith('/tokens')
        ? 'tokens'
        : pathname.endsWith('/keys')
          ? 'keys'
          : 'issuer'
  const meta = sectionMeta[activeSection]

  useEffect(() => {
    const navigation = settingsNavRef.current
    const activeLink = navigation?.querySelector<HTMLElement>('.is-active')
    if (!navigation || !activeLink || navigation.scrollWidth <= navigation.clientWidth) return

    const targetLeft = activeLink.offsetLeft - (navigation.clientWidth - activeLink.offsetWidth) / 2
    navigation.scrollTo({ left: Math.max(0, targetLeft), behavior: 'auto' })
  }, [activeSection])

  function saveSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSaved(true)
    window.setTimeout(() => setSaved(false), 2200)
  }

  async function copyIssuer() {
    await navigator.clipboard?.writeText('https://id.oneissuer.dev')
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  let headerActions: ReactNode
  if (activeSection === 'issuer') headerActions = <StatusPill tone="success">{t('common.verified')}</StatusPill>
  if (activeSection === 'registration') {
    headerActions = <Toggle checked={registrationEnabled} label={t('settings.registration.enable')} onChange={() => setRegistrationEnabled((value) => !value)} />
  }
  if (activeSection === 'keys') {
    headerActions = <button className="button button--secondary" type="button"><RefreshCw size={15} />{t('settings.keys.rotate')}</button>
  }

  return (
    <>
      <PageHeader
        actions={headerActions}
        eyebrow={t('settings.eyebrow')}
        title={t(meta.titleKey)}
        description={t(meta.descriptionKey)}
      />

      <form className="settings-layout settings-layout--pages" onSubmit={saveSettings}>
        <nav ref={settingsNavRef} className="settings-nav" aria-label={t('settings.sectionsAria')}>
          {settingsNavigation.map(({ end, icon: Icon, labelKey, path }) => (
            <NavLink className={({ isActive }) => isActive ? 'is-active' : ''} end={end} key={path} to={path}>
              <Icon size={16} />{t(labelKey)}
            </NavLink>
          ))}
        </nav>

        <div className="settings-content settings-content--page">
          {activeSection === 'issuer' && (
            <section className="panel settings-section settings-page-panel">
              <div className="settings-section__body">
                <label className="form-field">
                  <span>{t('settings.issuer.url')}</span>
                  <span className="input-shell input-shell--action"><LockKeyhole size={17} /><input name="issuer-url" readOnly value="https://id.oneissuer.dev" /><button className="input-action" onClick={copyIssuer} type="button" aria-label={t('settings.issuer.copy')}>{copied ? <Check size={16} /> : <Copy size={16} />}</button></span>
                  <small>{t('settings.issuer.immutable')}</small>
                </label>
                <a className="discovery-link" href="#discovery"><span><Globe2 size={16} /><code>/.well-known/openid-configuration</code></span><ExternalLink size={15} /></a>
              </div>
            </section>
          )}

          {activeSection === 'registration' && (
            <section className="panel settings-section settings-page-panel">
              <div className="settings-section__body">
                <div className="setting-row"><span><strong>{t('settings.registration.clientInitiated')}</strong><small>{t('settings.registration.clientInitiatedHelp')}</small></span><StatusPill tone={registrationEnabled ? 'success' : 'neutral'}>{registrationEnabled ? t('common.enabled') : t('common.disabled')}</StatusPill></div>
                <div className="setting-row"><span><strong>{t('settings.registration.emailVerification')}</strong><small>{t('settings.registration.emailVerificationHelp')}</small></span><select aria-label={t('settings.registration.emailPolicyAria')} className="compact-select" defaultValue="required" name="email-verification"><option value="required">{t('common.required')}</option><option value="optional">{t('common.optional')}</option><option value="disabled">{t('common.disabled')}</option></select></div>
                <div className="setting-row"><span><strong>{t('settings.registration.defaultPolicy')}</strong><small>{t('settings.registration.defaultPolicyHelp')}</small></span><select aria-label={t('settings.registration.defaultPolicyAria')} className="compact-select" defaultValue="allow" name="default-registration-policy"><option value="allow">{t('settings.registration.allow')}</option><option value="deny">{t('settings.registration.deny')}</option></select></div>
              </div>
            </section>
          )}

          {activeSection === 'authentication' && (
            <section className="panel settings-section settings-page-panel">
              <div className="settings-section__body auth-methods">
                <div className="setting-row"><span className="setting-with-icon"><i><LockKeyhole size={18} /></i><span><strong>{t('settings.authentication.emailPassword')}</strong><small>{t('settings.authentication.emailPasswordHelp')}</small></span></span><Toggle checked label={t('settings.authentication.enableEmail')} onChange={() => undefined} /></div>
                <div className="setting-row"><span className="setting-with-icon"><i><ShieldCheck size={18} /></i><span><strong>GitHub</strong><small>{t('settings.authentication.githubHelp')}</small></span></span><Toggle checked={githubEnabled} label={t('settings.authentication.enableGithub')} onChange={() => setGithubEnabled((value) => !value)} /></div>
                <div className="setting-row"><span className="setting-with-icon"><i><Fingerprint size={18} /></i><span><strong>{t('settings.authentication.passkeys')}</strong><small>{t('settings.authentication.passkeysHelp')}</small></span></span><Toggle checked={passkeysEnabled} label={t('settings.authentication.enablePasskeys')} onChange={() => setPasskeysEnabled((value) => !value)} /></div>
              </div>
            </section>
          )}

          {activeSection === 'tokens' && (
            <section className="panel settings-section settings-page-panel">
              <div className="settings-section__body token-fields">
                <label className="form-field"><span>{t('settings.tokens.idToken')}</span><span className="input-shell input-shell--suffix"><input defaultValue="5" inputMode="numeric" name="id-token-minutes" /><small>{t('settings.tokens.minutes')}</small></span></label>
                <label className="form-field"><span>{t('settings.tokens.accessToken')}</span><span className="input-shell input-shell--suffix"><input defaultValue="10" inputMode="numeric" name="access-token-minutes" /><small>{t('settings.tokens.minutes')}</small></span></label>
                <label className="form-field"><span>{t('settings.tokens.refreshToken')}</span><span className="input-shell input-shell--suffix"><input defaultValue="30" inputMode="numeric" name="refresh-token-days" /><small>{t('settings.tokens.days')}</small></span></label>
              </div>
            </section>
          )}

          {activeSection === 'keys' && (
            <section className="panel settings-section settings-page-panel">
              <div className="settings-section__body">
                <div className="signing-key"><span className="signing-key__icon"><KeyRound size={21} /></span><span><strong>key_2026_07</strong><code>RS256 · SHA-256: 4F:9A:21:8C:7D:…</code></span><span><StatusPill tone="success">{t('common.active')}</StatusPill><small>{t('settings.keys.created', { date: formatDate('2026-07-01T12:00:00+08:00', { year: 'numeric', month: 'short', day: 'numeric' }) })}</small></span></div>
              </div>
            </section>
          )}

          <div className="settings-savebar"><span>{t('settings.saveHint')}</span><button className="button button--primary" type="submit"><Save size={16} />{t('settings.save')}</button></div>
        </div>
      </form>

      {saved && <div className="save-toast" role="status"><Check size={17} />{t('settings.saved')}</div>}
    </>
  )
}
