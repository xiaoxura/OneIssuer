export type UserStatus = 'active' | 'invited' | 'suspended'
export type MfaMethod = 'passkey' | 'totp' | 'notEnrolled' | 'none'
export type AvatarTone = 'mint' | 'blue' | 'amber' | 'rose' | 'violet' | 'slate'
export type PrototypeLocation = 'shanghai' | 'singapore' | 'mumbai' | 'lisbon' | 'seoul'
export type RelativeTimeValue = {
  value: number
  unit: 'minute' | 'hour' | 'day'
}

export type PrototypeUser = {
  id: string
  name: string
  email: string
  initials: string
  tone: AvatarTone
  status: UserStatus
  lastSeen: RelativeTimeValue | null
  mfa: MfaMethod
  created: string
  applications: number
}

export const users: PrototypeUser[] = [
  {
    id: 'usr_01J9A3K7MTV1',
    name: 'Maya Chen',
    email: 'maya@acme.dev',
    initials: 'MC',
    tone: 'mint',
    status: 'active',
    lastSeen: { value: -2, unit: 'minute' },
    mfa: 'passkey',
    created: '2026-07-18T12:00:00+08:00',
    applications: 6,
  },
  {
    id: 'usr_01J9B8N2RXF4',
    name: 'Jordan Lee',
    email: 'jordan@acme.dev',
    initials: 'JL',
    tone: 'blue',
    status: 'active',
    lastSeen: { value: -18, unit: 'minute' },
    mfa: 'totp',
    created: '2026-07-15T12:00:00+08:00',
    applications: 4,
  },
  {
    id: 'usr_01J9CJW6QTP7',
    name: 'Priya Shah',
    email: 'priya@acme.dev',
    initials: 'PS',
    tone: 'violet',
    status: 'active',
    lastSeen: { value: -1, unit: 'hour' },
    mfa: 'notEnrolled',
    created: '2026-07-12T12:00:00+08:00',
    applications: 3,
  },
  {
    id: 'usr_01J9D4R8HYK2',
    name: 'Marcus Reed',
    email: 'marcus@acme.dev',
    initials: 'MR',
    tone: 'amber',
    status: 'invited',
    lastSeen: null,
    mfa: 'none',
    created: '2026-07-10T12:00:00+08:00',
    applications: 0,
  },
  {
    id: 'usr_01J9E9M3LVN5',
    name: 'Sofia Costa',
    email: 'sofia@acme.dev',
    initials: 'SC',
    tone: 'rose',
    status: 'suspended',
    lastSeen: { value: -3, unit: 'day' },
    mfa: 'totp',
    created: '2026-06-28T12:00:00+08:00',
    applications: 2,
  },
  {
    id: 'usr_01J9FKQ5BXD9',
    name: 'Noah Kim',
    email: 'noah@acme.dev',
    initials: 'NK',
    tone: 'slate',
    status: 'active',
    lastSeen: { value: -5, unit: 'day' },
    mfa: 'passkey',
    created: '2026-06-21T12:00:00+08:00',
    applications: 5,
  },
]

export type ApplicationType = 'web' | 'spa' | 'native'
export type ApplicationStatus = 'live' | 'development'

export type PrototypeApplication = {
  id: string
  name: string
  initials: string
  tone: AvatarTone
  type: ApplicationType
  clientId: string
  signIns: number
  status: ApplicationStatus
  redirectUri: string
  updated: RelativeTimeValue
}

export const applications: PrototypeApplication[] = [
  {
    id: 'app_acme_workspace',
    name: 'Acme Workspace',
    initials: 'AW',
    tone: 'mint',
    type: 'web',
    clientId: 'app_acme_workspace',
    signIns: 2400,
    status: 'live',
    redirectUri: 'https://app.acme.dev/auth/callback',
    updated: { value: -8, unit: 'minute' },
  },
  {
    id: 'app_canvas',
    name: 'Canvas Studio',
    initials: 'CS',
    tone: 'violet',
    type: 'spa',
    clientId: 'app_canvas_studio',
    signIns: 987,
    status: 'live',
    redirectUri: 'https://canvas.acme.dev/callback',
    updated: { value: -2, unit: 'hour' },
  },
  {
    id: 'app_docs',
    name: 'Developer Docs',
    initials: 'DD',
    tone: 'blue',
    type: 'web',
    clientId: 'app_developer_docs',
    signIns: 418,
    status: 'live',
    redirectUri: 'https://docs.acme.dev/oidc/callback',
    updated: { value: -1, unit: 'day' },
  },
  {
    id: 'app_cli',
    name: 'OneIssuer CLI',
    initials: 'OI',
    tone: 'amber',
    type: 'native',
    clientId: 'app_oneissuer_cli',
    signIns: 64,
    status: 'development',
    redirectUri: 'http://127.0.0.1:8787/callback',
    updated: { value: -3, unit: 'day' },
  },
]

export type ResultStatus = 'success' | 'warning' | 'denied'

export const recentSignIns: Array<{
  user: PrototypeUser
  application: string
  location: PrototypeLocation
  time: RelativeTimeValue
  result: Extract<ResultStatus, 'success' | 'denied'>
}> = [
  { user: users[0], application: 'Acme Workspace', location: 'shanghai', time: { value: -2, unit: 'minute' }, result: 'success' },
  { user: users[1], application: 'Canvas Studio', location: 'singapore', time: { value: -18, unit: 'minute' }, result: 'success' },
  { user: users[2], application: 'Developer Docs', location: 'mumbai', time: { value: -1, unit: 'hour' }, result: 'success' },
  { user: users[4], application: 'Acme Workspace', location: 'lisbon', time: { value: -3, unit: 'hour' }, result: 'denied' },
]

export type AuditCategory = 'authentication' | 'user' | 'application' | 'security'
export type AuditAction =
  | 'userSignedIn'
  | 'refreshTokenRotated'
  | 'applicationUpdated'
  | 'challengeFailed'
  | 'userInvited'
  | 'keyNearingRotation'

export type AuditEvent = {
  id: string
  action: AuditAction
  category: AuditCategory
  actor: string
  target: string
  ip: string
  time: string
  result: ResultStatus
}

export const auditEvents: AuditEvent[] = [
  { id: 'evt_8F2A', action: 'userSignedIn', category: 'authentication', actor: 'maya@acme.dev', target: 'Acme Workspace', ip: '116.228.84.12', time: '2026-07-31T14:28:12+08:00', result: 'success' },
  { id: 'evt_8F19', action: 'refreshTokenRotated', category: 'security', actor: 'System', target: 'ses_01JAV7', ip: '116.228.84.12', time: '2026-07-31T14:27:54+08:00', result: 'success' },
  { id: 'evt_8EFD', action: 'applicationUpdated', category: 'application', actor: 'alex@oneissuer.dev', target: 'Canvas Studio', ip: '10.24.8.4', time: '2026-07-31T13:04:33+08:00', result: 'success' },
  { id: 'evt_8EC2', action: 'challengeFailed', category: 'authentication', actor: 'sofia@acme.dev', target: 'Acme Workspace', ip: '185.113.42.9', time: '2026-07-31T11:42:08+08:00', result: 'denied' },
  { id: 'evt_8D91', action: 'userInvited', category: 'user', actor: 'alex@oneissuer.dev', target: 'marcus@acme.dev', ip: '10.24.8.4', time: '2026-07-31T09:18:45+08:00', result: 'success' },
  { id: 'evt_8C44', action: 'keyNearingRotation', category: 'security', actor: 'System', target: 'key_2026_07', ip: '—', time: '2026-07-30T23:00:00+08:00', result: 'warning' },
]

export type PrototypeSession = {
  id: string
  user: PrototypeUser
  device: string
  browser: string
  location: PrototypeLocation
  ip: string
  created: string
  lastActive: RelativeTimeValue
  current?: boolean
}

export const initialSessions: PrototypeSession[] = [
  { id: 'ses_01JAV7', user: users[0], device: 'MacBook Pro', browser: 'Chrome 137 · macOS', location: 'shanghai', ip: '116.228.84.12', created: '2026-07-31T09:12:00+08:00', lastActive: { value: 0, unit: 'minute' }, current: true },
  { id: 'ses_01JAT9', user: users[1], device: 'iPhone 17', browser: 'Safari · iOS', location: 'singapore', ip: '103.21.244.7', created: '2026-07-31T08:42:00+08:00', lastActive: { value: -18, unit: 'minute' } },
  { id: 'ses_01J9Z3', user: users[2], device: 'ThinkPad X1', browser: 'Firefox 141 · Linux', location: 'mumbai', ip: '49.36.82.14', created: '2026-07-30T16:20:00+08:00', lastActive: { value: -1, unit: 'hour' } },
  { id: 'ses_01J8M1', user: users[5], device: 'Pixel 11', browser: 'Chrome · Android', location: 'seoul', ip: '121.134.8.31', created: '2026-07-27T11:04:00+08:00', lastActive: { value: -5, unit: 'day' } },
]

export const signInSeries = [
  { date: '2026-07-24T12:00:00+08:00', success: 360, failed: 28 },
  { date: '2026-07-25T12:00:00+08:00', success: 280, failed: 20 },
  { date: '2026-07-26T12:00:00+08:00', success: 245, failed: 18 },
  { date: '2026-07-27T12:00:00+08:00', success: 510, failed: 46 },
  { date: '2026-07-28T12:00:00+08:00', success: 470, failed: 34 },
  { date: '2026-07-29T12:00:00+08:00', success: 620, failed: 51 },
  { date: '2026-07-30T12:00:00+08:00', success: 552, failed: 39 },
]
