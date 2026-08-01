import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { I18nContext, type I18nContextValue, type Locale, type Translate, type TranslationValues } from './context'
import { enMessages, type TranslationKey } from './messages.en'
import { zhCNMessages } from './messages.zh-CN'

const STORAGE_KEY = 'oneissuer.locale'

const resources: Record<Locale, Record<TranslationKey, string>> = {
  en: enMessages,
  'zh-CN': zhCNMessages,
}

function isLocale(value: string | null): value is Locale {
  return value === 'en' || value === 'zh-CN'
}

function detectLocale(): Locale {
  const stored = window.localStorage.getItem(STORAGE_KEY)
  if (isLocale(stored)) return stored

  const browserLanguages = navigator.languages?.length ? navigator.languages : [navigator.language]
  return browserLanguages.some((language) => language.toLowerCase().startsWith('zh')) ? 'zh-CN' : 'en'
}

function interpolate(message: string, values?: TranslationValues) {
  if (!values) return message
  return message.replace(/\{(\w+)\}/g, (match, key: string) => (
    Object.hasOwn(values, key) ? String(values[key]) : match
  ))
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>(detectLocale)

  const t = useCallback<Translate>(
    (key, values) => interpolate(resources[locale][key] ?? enMessages[key] ?? key, values),
    [locale],
  )

  const formatNumber = useCallback(
    (value: number, options?: Intl.NumberFormatOptions) => new Intl.NumberFormat(locale, options).format(value),
    [locale],
  )

  const formatDate = useCallback(
    (value: string | number | Date, options?: Intl.DateTimeFormatOptions) => (
      new Intl.DateTimeFormat(locale, options).format(new Date(value))
    ),
    [locale],
  )

  const formatRelativeTime = useCallback(
    (value: number, unit: Intl.RelativeTimeFormatUnit) => (
      new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(value, unit)
    ),
    [locale],
  )

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, locale)
    document.documentElement.lang = locale
    document.title = locale === 'zh-CN' ? 'OneIssuer · 统一身份认证' : 'OneIssuer · Unified identity'
    document.querySelector<HTMLMetaElement>('meta[name="description"]')?.setAttribute('content', t('meta.description'))
  }, [locale, t])

  const value = useMemo<I18nContextValue>(
    () => ({ locale, setLocale, t, formatNumber, formatDate, formatRelativeTime }),
    [formatDate, formatNumber, formatRelativeTime, locale, t],
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}
