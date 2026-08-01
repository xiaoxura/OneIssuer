import { createContext, useContext } from 'react'
import type { TranslationKey } from './messages.en'

export type Locale = 'en' | 'zh-CN'
export type TranslationValues = Record<string, string | number>
export type Translate = (key: TranslationKey, values?: TranslationValues) => string

export type I18nContextValue = {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: Translate
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string
  formatDate: (value: string | number | Date, options?: Intl.DateTimeFormatOptions) => string
  formatRelativeTime: (value: number, unit: Intl.RelativeTimeFormatUnit) => string
}

export const I18nContext = createContext<I18nContextValue | null>(null)

export function useI18n() {
  const value = useContext(I18nContext)
  if (!value) throw new Error('useI18n must be used inside I18nProvider')
  return value
}
