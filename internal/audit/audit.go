// Package audit defines an append-only, value-free security event model. Its
// changed-field list contains schema keys only, never submitted values.
package audit

import (
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"
)

// EventType is a fixed security-event identifier.
type EventType string

// Result is a fixed audit outcome classification.
type Result string

// TargetType identifies the kind of resource affected by an event.
type TargetType string

// Supported fixed security event types through phase four.
const (
	AdminBootstrapSucceeded            EventType = "admin_bootstrap_succeeded"
	AdminBootstrapRejected             EventType = "admin_bootstrap_rejected"
	UserRegistered                     EventType = "user_registered"
	UserRegistrationRejected           EventType = "user_registration_rejected"
	UserCreated                        EventType = "user_created"
	UserUpdated                        EventType = "user_updated"
	UserStatusChanged                  EventType = "user_status_changed"
	UserRoleChanged                    EventType = "user_role_changed"
	LoginSucceeded                     EventType = "login_succeeded"
	LoginFailed                        EventType = "login_failed"
	LoginDisabledUser                  EventType = "login_disabled_user"
	SessionCreated                     EventType = "session_created"
	SessionRevoked                     EventType = "session_revoked"
	SessionsRevokedAll                 EventType = "sessions_revoked_all"
	ClientCreated                      EventType = "client_created"
	ClientUpdated                      EventType = "client_updated"
	ClientDisabled                     EventType = "client_disabled"
	ClientSecretRotated                EventType = "client_secret_rotated"
	AuthorizationTransactionCreated    EventType = "authorization_transaction_created"
	AuthorizationTransactionConsumed   EventType = "authorization_transaction_consumed"
	AuthorizationTransactionExpired    EventType = "authorization_transaction_expired"
	AuthorizationTransactionRejected   EventType = "authorization_transaction_rejected"
	AuthorizationGranted               EventType = "authorization_granted"
	AuthorizationDenied                EventType = "authorization_denied"
	AuthorizationCodeIssued            EventType = "authorization_code_issued"
	AuthorizationCodeExchangeSucceeded EventType = "authorization_code_exchange_succeeded"
	AuthorizationCodeExchangeRejected  EventType = "authorization_code_exchange_rejected"
	ConsentGrantCreated                EventType = "consent_grant_created"
	ConsentGrantExpanded               EventType = "consent_grant_expanded"
	AccessTokenIssued                  EventType = "access_token_issued"
	SigningKeyLoaded                   EventType = "signing_key_loaded"
	RefreshTokenIssued                 EventType = "refresh_token_issued"
	RefreshTokenRotated                EventType = "refresh_token_rotated"
	RefreshTokenExchangeRejected       EventType = "refresh_token_exchange_rejected"
	RefreshTokenReuseDetected          EventType = "refresh_token_reuse_detected"
	RefreshTokenFamilyRevoked          EventType = "refresh_token_family_revoked"
	AccessTokenRevoked                 EventType = "access_token_revoked"
	ConsentGrantRevoked                EventType = "consent_grant_revoked"
	ConsentGrantReactivated            EventType = "consent_grant_reactivated"
	RPLogoutCompleted                  EventType = "rp_logout_completed"
	LogoutTransactionRejected          EventType = "logout_transaction_rejected"
)

// Supported audit result classifications.
const (
	ResultSuccess  Result = "success"
	ResultRejected Result = "rejected"
	ResultFailure  Result = "failure"
)

// Supported audit target classifications.
const (
	TargetUser              TargetType = "user"
	TargetClient            TargetType = "client"
	TargetSession           TargetType = "session"
	TargetAuthTransaction   TargetType = "auth_transaction"
	TargetConsentGrant      TargetType = "consent_grant"
	TargetAuthorizationCode TargetType = "authorization_code"
	TargetAccessToken       TargetType = "access_token"
	TargetRefreshToken      TargetType = "refresh_token"
	TargetRefreshFamily     TargetType = "refresh_token_family"
	TargetLogoutTransaction TargetType = "logout_transaction"
)

var (
	// ErrInvalidEvent identifies an event outside the fixed audit schema.
	ErrInvalidEvent  = errors.New("invalid audit event")
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	validEvents      = set(
		string(AdminBootstrapSucceeded), string(AdminBootstrapRejected),
		string(UserRegistered), string(UserRegistrationRejected), string(UserCreated),
		string(UserUpdated), string(UserStatusChanged), string(UserRoleChanged),
		string(LoginSucceeded), string(LoginFailed), string(LoginDisabledUser),
		string(SessionCreated), string(SessionRevoked), string(SessionsRevokedAll),
		string(ClientCreated), string(ClientUpdated), string(ClientDisabled), string(ClientSecretRotated),
		string(AuthorizationTransactionCreated), string(AuthorizationTransactionConsumed),
		string(AuthorizationTransactionExpired), string(AuthorizationTransactionRejected),
		string(AuthorizationGranted), string(AuthorizationDenied), string(AuthorizationCodeIssued),
		string(AuthorizationCodeExchangeSucceeded), string(AuthorizationCodeExchangeRejected),
		string(ConsentGrantCreated), string(ConsentGrantExpanded), string(AccessTokenIssued), string(SigningKeyLoaded),
		string(RefreshTokenIssued), string(RefreshTokenRotated), string(RefreshTokenExchangeRejected),
		string(RefreshTokenReuseDetected), string(RefreshTokenFamilyRevoked), string(AccessTokenRevoked),
		string(ConsentGrantRevoked), string(ConsentGrantReactivated), string(RPLogoutCompleted),
		string(LogoutTransactionRejected),
	)
	validResults       = set(string(ResultSuccess), string(ResultRejected), string(ResultFailure))
	validTargets       = set(string(TargetUser), string(TargetClient), string(TargetSession), string(TargetAuthTransaction), string(TargetConsentGrant), string(TargetAuthorizationCode), string(TargetAccessToken), string(TargetRefreshToken), string(TargetRefreshFamily), string(TargetLogoutTransaction))
	validChangedFields = set(
		"status", "role", "username", "display_name", "email", "name", "description",
		"logo_uri", "registration_enabled", "redirect_uris", "logout_uris", "scopes",
		"secret", "revoked", "created", "expanded", "issued", "consumed",
		"rotated", "reused", "reactivated",
	)
)

// Event is the only audit write model accepted by persistence adapters.
type Event struct {
	ID            uuid.UUID   `json:"id"`
	Type          EventType   `json:"event_type"`
	Result        Result      `json:"result"`
	ActorUserID   *uuid.UUID  `json:"actor_user_id,omitempty"`
	TargetType    *TargetType `json:"target_type,omitempty"`
	TargetID      *uuid.UUID  `json:"target_id,omitempty"`
	RequestID     string      `json:"request_id,omitempty"`
	ChangedFields []string    `json:"changed_fields"`
	OccurredAt    time.Time   `json:"occurred_at"`
}

// New creates and validates an event while canonicalizing changed-field order.
func New(eventType EventType, result Result, actor *uuid.UUID, targetType TargetType, target *uuid.UUID, requestID string, changed []string, at time.Time) (Event, error) {
	event := Event{
		ID: uuid.New(), Type: eventType, Result: result, ActorUserID: actor,
		RequestID: requestID, ChangedFields: append([]string{}, changed...), OccurredAt: at.UTC(),
	}
	if targetType != "" || target != nil {
		targetCopy := targetType
		event.TargetType = &targetCopy
		event.TargetID = target
	}
	sort.Strings(event.ChangedFields)
	event.ChangedFields = compact(event.ChangedFields)
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	return event, nil
}

// Validate prevents arbitrary caller-controlled metadata from entering audit.
func (e Event) Validate() error {
	if e.ID == uuid.Nil || !validEvents[string(e.Type)] || !validResults[string(e.Result)] || e.OccurredAt.IsZero() {
		return ErrInvalidEvent
	}
	if e.RequestID != "" && !requestIDPattern.MatchString(e.RequestID) {
		return ErrInvalidEvent
	}
	if (e.TargetType == nil) != (e.TargetID == nil) {
		return ErrInvalidEvent
	}
	if e.TargetType != nil && (!validTargets[string(*e.TargetType)] || *e.TargetID == uuid.Nil) {
		return ErrInvalidEvent
	}
	for _, field := range e.ChangedFields {
		if !validChangedFields[field] {
			return ErrInvalidEvent
		}
	}
	return nil
}

// ValidEventType constrains administrative audit filters to the frozen enum.
func ValidEventType(value string) bool { return value == "" || validEvents[value] }

func set(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func compact(values []string) []string {
	if len(values) < 2 {
		return values
	}
	output := values[:1]
	for _, value := range values[1:] {
		if value != output[len(output)-1] {
			output = append(output, value)
		}
	}
	return output
}
