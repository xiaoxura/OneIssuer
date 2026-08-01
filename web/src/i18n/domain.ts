import type {
  ApplicationStatus,
  ApplicationType,
  AuditAction,
  AuditCategory,
  MfaMethod,
  PrototypeLocation,
  ResultStatus,
  UserStatus,
} from '../data/mock'
import type { TranslationKey } from './messages.en'

export const USER_STATUS_KEYS = {
  active: 'status.user.active',
  invited: 'status.user.invited',
  suspended: 'status.user.suspended',
} satisfies Record<UserStatus, TranslationKey>

export const MFA_KEYS = {
  passkey: 'mfa.passkey',
  totp: 'mfa.totp',
  notEnrolled: 'mfa.notEnrolled',
  none: 'mfa.none',
} satisfies Record<MfaMethod, TranslationKey>

export const APPLICATION_TYPE_KEYS = {
  web: 'application.type.web',
  spa: 'application.type.spa',
  native: 'application.type.native',
} satisfies Record<ApplicationType, TranslationKey>

export const APPLICATION_STATUS_KEYS = {
  live: 'common.live',
  development: 'common.development',
} satisfies Record<ApplicationStatus, TranslationKey>

export const RESULT_STATUS_KEYS = {
  success: 'status.result.success',
  warning: 'status.result.warning',
  denied: 'status.result.denied',
} satisfies Record<ResultStatus, TranslationKey>

export const LOCATION_KEYS = {
  shanghai: 'location.shanghai',
  singapore: 'location.singapore',
  mumbai: 'location.mumbai',
  lisbon: 'location.lisbon',
  seoul: 'location.seoul',
} satisfies Record<PrototypeLocation, TranslationKey>

export const AUDIT_CATEGORY_KEYS = {
  authentication: 'audit.category.authentication',
  user: 'audit.category.user',
  application: 'audit.category.application',
  security: 'audit.category.security',
} satisfies Record<AuditCategory, TranslationKey>

export const AUDIT_ACTION_KEYS = {
  userSignedIn: 'audit.action.userSignedIn',
  refreshTokenRotated: 'audit.action.refreshTokenRotated',
  applicationUpdated: 'audit.action.applicationUpdated',
  challengeFailed: 'audit.action.challengeFailed',
  userInvited: 'audit.action.userInvited',
  keyNearingRotation: 'audit.action.keyNearingRotation',
} satisfies Record<AuditAction, TranslationKey>
