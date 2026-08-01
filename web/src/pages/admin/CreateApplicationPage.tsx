import { useState, type FormEvent } from 'react'
import {
  ArrowLeft,
  Check,
  Code2,
  Globe2,
  Info,
  LockKeyhole,
  Plus,
  ShieldCheck,
  Terminal,
  Trash2,
} from 'lucide-react'
import { Link } from '../../router'
import { useNavigate } from '../../router-context'
import { PageHeader } from '../../components/ui'
import { useI18n, type TranslationKey } from '../../i18n'

const applicationTypes = [
  { id: 'web', labelKey: 'application.type.web', descriptionKey: 'createApplication.webDescription', icon: Globe2 },
  { id: 'spa', labelKey: 'application.type.spa', descriptionKey: 'createApplication.spaDescription', icon: Code2 },
  { id: 'native', labelKey: 'application.type.native', descriptionKey: 'createApplication.nativeDescription', icon: Terminal },
] as const satisfies ReadonlyArray<{ id: string; labelKey: TranslationKey; descriptionKey: TranslationKey; icon: typeof Globe2 }>

export function CreateApplicationPage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [applicationType, setApplicationType] = useState<(typeof applicationTypes)[number]['id']>('web')
  const [redirectUris, setRedirectUris] = useState(['https://app.example.com/auth/callback'])

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    navigate('/admin/applications')
  }

  function updateRedirectUri(index: number, value: string) {
    setRedirectUris((current) => current.map((uri, uriIndex) => (uriIndex === index ? value : uri)))
  }

  function removeRedirectUri(index: number) {
    setRedirectUris((current) => current.filter((_, uriIndex) => uriIndex !== index))
  }

  return (
    <>
      <Link className="back-link" to="/admin/applications"><ArrowLeft size={15} />{t('createApplication.back')}</Link>
      <PageHeader
        eyebrow={t('createApplication.eyebrow')}
        title={t('createApplication.title')}
        description={t('createApplication.description')}
      />

      <form className="create-application-layout" onSubmit={handleSubmit}>
        <div className="create-application-main">
          <section className="panel form-section">
            <header><span>1</span><div><h2>{t('createApplication.typeTitle')}</h2><p>{t('createApplication.typeDescription')}</p></div></header>
            <div className="application-type-grid">
              {applicationTypes.map(({ id, labelKey, descriptionKey, icon: Icon }) => (
                <button
                  className={applicationType === id ? 'application-type is-selected' : 'application-type'}
                  key={id}
                  onClick={() => setApplicationType(id)}
                  type="button"
                >
                  <span className="application-type__check"><Check size={13} /></span>
                  <span className="application-type__icon"><Icon size={21} /></span>
                  <strong>{t(labelKey)}</strong>
                  <small>{t(descriptionKey)}</small>
                </button>
              ))}
            </div>
          </section>

          <section className="panel form-section">
            <header><span>2</span><div><h2>{t('createApplication.detailsTitle')}</h2><p>{t('createApplication.detailsDescription')}</p></div></header>
            <div className="form-section__body form-stack">
              <label className="form-field"><span>{t('createApplication.name')}</span><span className="input-shell"><input placeholder="Acme Workspace" required /></span><small>{t('createApplication.nameHelp')}</small></label>
              <div className="form-grid form-grid--two">
                <label className="form-field"><span>{t('createApplication.homepageUrl')}</span><span className="input-shell"><input placeholder="https://app.example.com" type="url" /></span></label>
                <label className="form-field"><span>{t('createApplication.privacyUrl')}</span><span className="input-shell"><input placeholder="https://example.com/privacy" type="url" /></span></label>
              </div>
              <label className="upload-field">
                <span className="application-mark application-mark--mint">A</span>
                <span><strong>{t('createApplication.logo')}</strong><small>{t('createApplication.logoHelp')}</small></span>
                <input accept="image/*" type="file" />
                <span className="button button--secondary">{t('createApplication.uploadLogo')}</span>
              </label>
            </div>
          </section>

          <section className="panel form-section">
            <header><span>3</span><div><h2>{t('createApplication.redirectTitle')}</h2><p>{t('createApplication.redirectDescription')}</p></div></header>
            <div className="form-section__body form-stack">
              {redirectUris.map((uri, index) => (
                <label className="form-field" key={`redirect-${index}`}>
                  <span>{t('createApplication.callbackUrl', { index: redirectUris.length > 1 ? ` ${index + 1}` : '' })}</span>
                  <span className="input-shell input-shell--action">
                    <Globe2 size={17} />
                    <input onChange={(event) => updateRedirectUri(index, event.target.value)} required type="url" value={uri} />
                    {redirectUris.length > 1 && <button className="input-action input-action--danger" onClick={() => removeRedirectUri(index)} type="button" aria-label={t('createApplication.removeRedirect')}><Trash2 size={16} /></button>}
                  </span>
                </label>
              ))}
              <button className="inline-add" onClick={() => setRedirectUris((current) => [...current, ''])} type="button"><Plus size={15} />{t('createApplication.addUri')}</button>
              <div className="inline-notice"><Info size={16} /><span>{t('createApplication.wildcardNotice')}</span></div>
            </div>
          </section>
        </div>

        <aside className="create-application-aside">
          <section className="panel configuration-summary">
            <span className="panel__eyebrow">{t('createApplication.configuration')}</span>
            <h2>{t('createApplication.securityDefaults')}</h2>
            <div className="security-default"><span><ShieldCheck size={17} /></span><div><strong>{t('createApplication.authorizationCode')}</strong><small>{t('createApplication.authorizationCodeHelp')}</small></div><Check size={16} /></div>
            <div className="security-default"><span><LockKeyhole size={17} /></span><div><strong>PKCE · S256</strong><small>{t('createApplication.pkceHelp')}</small></div><Check size={16} /></div>
            <div className="security-default"><span><Globe2 size={17} /></span><div><strong>{t('createApplication.exactRedirect')}</strong><small>{t('createApplication.exactRedirectHelp')}</small></div><Check size={16} /></div>
            <div className="summary-values"><div><span>{t('createApplication.clientType')}</span><strong>{applicationType === 'web' ? t('createApplication.confidential') : t('createApplication.public')}</strong></div><div><span>{t('createApplication.subjectType')}</span><strong>{t('createApplication.public')}</strong></div><div><span>{t('createApplication.signingAlgorithm')}</span><strong>RS256</strong></div></div>
          </section>
          <div className="create-actions">
            <button className="button button--primary button--full" type="submit">{t('createApplication.create')}</button>
            <Link className="button button--secondary button--full" to="/admin/applications">{t('common.cancel')}</Link>
          </div>
          <p className="aside-help">{t('createApplication.needHelp')} <a href="#integration">{t('createApplication.integrationGuide')}</a>{t('common.sentenceEnd')}</p>
        </aside>
      </form>
    </>
  )
}
