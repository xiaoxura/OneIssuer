import { Languages } from 'lucide-react'
import { useI18n, type Locale } from '../i18n'

export function LanguageSwitcher({ inverse = false }: { inverse?: boolean }) {
  const { locale, setLocale, t } = useI18n()

  function selectLocale(nextLocale: Locale) {
    setLocale(nextLocale)
  }

  return (
    <div
      aria-label={t('language.label')}
      className={`language-switcher ${inverse ? 'language-switcher--inverse' : ''}`}
      role="group"
    >
      <Languages aria-hidden="true" size={15} />
      <button
        aria-pressed={locale === 'zh-CN'}
        className={locale === 'zh-CN' ? 'is-active' : ''}
        onClick={() => selectLocale('zh-CN')}
        title={t('language.chinese')}
        type="button"
      >
        中
      </button>
      <span aria-hidden="true" />
      <button
        aria-pressed={locale === 'en'}
        className={locale === 'en' ? 'is-active' : ''}
        onClick={() => selectLocale('en')}
        title={t('language.english')}
        type="button"
      >
        EN
      </button>
    </div>
  )
}
