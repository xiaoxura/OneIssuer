import { Laptop, Monitor, Smartphone } from 'lucide-react'
import type { IconComponent } from '../../components/ui'
import type { TranslationKey } from '../../i18n'

export type ConnectedApplication = {
  id: string
  initials: string
  name: string
  tone: 'mint' | 'blue' | 'violet'
  typeKey: TranslationKey
  lastUsed: { value: number; unit: Intl.RelativeTimeFormatUnit }
  scopes: TranslationKey[]
}

export type AccountSession = {
  id: string
  icon: IconComponent
  device: string
  platform: string
  locationKey: TranslationKey
  lastActive: { value: number; unit: Intl.RelativeTimeFormatUnit }
  current?: boolean
}

export const initialApplications: ConnectedApplication[] = [
  {
    id: 'acme',
    initials: 'AW',
    name: 'Acme Workspace',
    tone: 'mint',
    typeKey: 'application.type.web',
    lastUsed: { value: -2, unit: 'minute' },
    scopes: ['account.apps.scope.profile', 'account.apps.scope.email'],
  },
  {
    id: 'canvas',
    initials: 'CS',
    name: 'Canvas Studio',
    tone: 'violet',
    typeKey: 'application.type.spa',
    lastUsed: { value: -18, unit: 'hour' },
    scopes: ['account.apps.scope.profile'],
  },
  {
    id: 'docs',
    initials: 'DD',
    name: 'Developer Docs',
    tone: 'blue',
    typeKey: 'application.type.web',
    lastUsed: { value: -4, unit: 'day' },
    scopes: ['account.apps.scope.profile', 'account.apps.scope.email'],
  },
]

export const initialSessions: AccountSession[] = [
  {
    id: 'current',
    icon: Monitor,
    device: 'MacBook Pro',
    platform: 'Chrome 138 · macOS',
    locationKey: 'location.shanghai',
    lastActive: { value: 0, unit: 'minute' },
    current: true,
  },
  {
    id: 'iphone',
    icon: Smartphone,
    device: 'iPhone 17',
    platform: 'Safari · iOS',
    locationKey: 'location.shanghai',
    lastActive: { value: -2, unit: 'hour' },
  },
  {
    id: 'thinkpad',
    icon: Laptop,
    device: 'ThinkPad X1',
    platform: 'Firefox 141 · Linux',
    locationKey: 'location.singapore',
    lastActive: { value: -3, unit: 'day' },
  },
]
