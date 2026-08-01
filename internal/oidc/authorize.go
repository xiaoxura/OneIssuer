package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	clientdomain "github.com/oneissuer/oneissuer/internal/client"
)

const (
	maxAuthorizeQueryBytes  = 8 << 10
	maxOpaqueParameterBytes = 1024
	maxAgeSeconds           = 30 * 24 * 60 * 60
)

// ErrorCode is an allowlisted OAuth/OIDC authorization error identifier.
type ErrorCode string

const (
	// ErrorInvalidRequest identifies malformed or ambiguous input.
	ErrorInvalidRequest ErrorCode = "invalid_request"
	// ErrorUnauthorizedClient identifies a Client not permitted for the request.
	ErrorUnauthorizedClient ErrorCode = "unauthorized_client"
	// ErrorUnsupportedResponseType identifies a response type outside Code Flow.
	ErrorUnsupportedResponseType ErrorCode = "unsupported_response_type"
	// ErrorInvalidScope identifies a Scope outside the active Client/profile set.
	ErrorInvalidScope ErrorCode = "invalid_scope"
	// ErrorServerError identifies an internal fail-closed authorization failure.
	ErrorServerError ErrorCode = "server_error"
	// ErrorTemporarilyUnavailable identifies a bounded transient failure.
	ErrorTemporarilyUnavailable ErrorCode = "temporarily_unavailable"
	// ErrorUnsupportedResponseMode identifies a response mode other than query.
	ErrorUnsupportedResponseMode ErrorCode = "unsupported_response_mode"
	// ErrorLoginRequired identifies a silent request that requires authentication.
	ErrorLoginRequired ErrorCode = "login_required"
	// ErrorConsentRequired identifies a silent request without a covering Grant.
	ErrorConsentRequired ErrorCode = "consent_required"
	// ErrorInteractionRequired identifies another required browser interaction.
	ErrorInteractionRequired ErrorCode = "interaction_required"
	// ErrorAccessDenied identifies an explicit user denial.
	ErrorAccessDenied ErrorCode = "access_denied"
	// ErrorRequestNotSupported identifies unsupported request-object input.
	ErrorRequestNotSupported ErrorCode = "request_not_supported"
	// ErrorRequestURINotSupported identifies unsupported request_uri input.
	ErrorRequestURINotSupported ErrorCode = "request_uri_not_supported"
)

// AuthorizationError carries only validated redirect state. Error() deliberately
// excludes RedirectURI and State so accidental logging remains value-free.
type AuthorizationError struct {
	Code           ErrorCode
	HTTPStatus     int
	SafeToRedirect bool
	RedirectURI    string
	State          string
}

func (e *AuthorizationError) Error() string {
	if e == nil || e.Code == "" {
		return "OIDC authorization request failed"
	}
	return "OIDC authorization request failed: " + string(e.Code)
}

// PromptSet is a canonical, duplicate-free prompt selection.
type PromptSet struct {
	values []string
}

// Values returns a defensive canonical copy.
func (p PromptSet) Values() []string { return append([]string(nil), p.values...) }

// Has reports whether a prompt value was requested.
func (p PromptSet) Has(value string) bool {
	index := sort.SearchStrings(p.values, value)
	return index < len(p.values) && p.values[index] == value
}

// VerifiedAuthorizationRequest contains only context validated against an active
// Client. It is safe to pass into authflow.CreateVerified, but its opaque fields
// remain sensitive and must not be logged.
type VerifiedAuthorizationRequest struct {
	Client        clientdomain.Client
	RedirectURI   string
	ResponseType  string
	ResponseMode  string
	Scopes        []string
	PKCEChallenge string
	State         string
	Nonce         string
	Prompts       PromptSet
	MaxAge        *uint32
}

// AuthorizationClientResolver reuses the phase-two Client registry and exact URI
// policy rather than creating a second protocol-side store.
type AuthorizationClientResolver interface {
	ResolveActive(context.Context, string) (clientdomain.Client, error)
	RedirectURIMatches(clientdomain.Client, string) bool
}

// ParseAuthorizationRequest applies the redirect trust state machine in a fixed
// order: syntax, unique Client, active Client, exact Redirect URI, then all other
// protocol parameters.
func ParseAuthorizationRequest(ctx context.Context, rawQuery string, clients AuthorizationClientResolver) (VerifiedAuthorizationRequest, error) {
	if clients == nil || len(rawQuery) > maxAuthorizeQueryBytes || !utf8.ValidString(rawQuery) {
		return VerifiedAuthorizationRequest{}, localAuthorizationError(ErrorInvalidRequest, http.StatusBadRequest)
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || !validQueryUTF8(values) {
		return VerifiedAuthorizationRequest{}, localAuthorizationError(ErrorInvalidRequest, http.StatusBadRequest)
	}

	if len(values["client_id"]) != 1 || values.Get("client_id") == "" || len(values["redirect_uri"]) != 1 || values.Get("redirect_uri") == "" {
		return VerifiedAuthorizationRequest{}, localAuthorizationError(ErrorInvalidRequest, http.StatusBadRequest)
	}
	clientValue, err := clients.ResolveActive(ctx, values.Get("client_id"))
	if err != nil {
		if errors.Is(err, clientdomain.ErrNotFound) {
			return VerifiedAuthorizationRequest{}, localAuthorizationError(ErrorInvalidRequest, http.StatusBadRequest)
		}
		return VerifiedAuthorizationRequest{}, localAuthorizationError(ErrorServerError, http.StatusInternalServerError)
	}
	redirectURI := values.Get("redirect_uri")
	if !clients.RedirectURIMatches(clientValue, redirectURI) {
		return VerifiedAuthorizationRequest{}, localAuthorizationError(ErrorInvalidRequest, http.StatusBadRequest)
	}

	state := ""
	if len(values["state"]) == 1 && validOpaqueParameter(values.Get("state")) {
		state = values.Get("state")
	}
	trustedError := func(code ErrorCode) error {
		return &AuthorizationError{
			Code: code, HTTPStatus: http.StatusFound, SafeToRedirect: true,
			RedirectURI: redirectURI, State: state,
		}
	}

	securityParameters := []string{
		"client_id", "redirect_uri", "response_type", "response_mode", "scope",
		"code_challenge", "code_challenge_method", "state", "nonce", "prompt", "max_age",
	}
	for _, name := range securityParameters {
		if len(values[name]) > 1 {
			return VerifiedAuthorizationRequest{}, trustedError(ErrorInvalidRequest)
		}
	}
	if len(values["request"]) > 0 {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorRequestNotSupported)
	}
	if len(values["request_uri"]) > 0 {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorRequestURINotSupported)
	}
	for _, required := range []string{"response_type", "scope", "code_challenge", "code_challenge_method"} {
		if len(values[required]) != 1 || values.Get(required) == "" {
			return VerifiedAuthorizationRequest{}, trustedError(ErrorInvalidRequest)
		}
	}
	if len(values["state"]) == 1 && !validOpaqueParameter(values.Get("state")) {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorInvalidRequest)
	}
	if len(values["nonce"]) == 1 && !validOpaqueParameter(values.Get("nonce")) {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorInvalidRequest)
	}

	if values.Get("response_type") != "code" {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorUnsupportedResponseType)
	}
	responseMode := "query"
	if len(values["response_mode"]) == 1 {
		if values.Get("response_mode") != "query" {
			return VerifiedAuthorizationRequest{}, trustedError(ErrorUnsupportedResponseMode)
		}
	}

	scopes, ok := parseScope(values.Get("scope"), clientValue.Scopes)
	if !ok {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorInvalidScope)
	}
	challenge := values.Get("code_challenge")
	if !validS256Challenge(challenge) || values.Get("code_challenge_method") != "S256" {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorInvalidRequest)
	}
	prompts, ok := parsePrompt(values["prompt"])
	if !ok {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorInvalidRequest)
	}
	maxAge, ok := parseMaxAge(values["max_age"])
	if !ok {
		return VerifiedAuthorizationRequest{}, trustedError(ErrorInvalidRequest)
	}

	return VerifiedAuthorizationRequest{
		Client: clientValue, RedirectURI: redirectURI, ResponseType: "code", ResponseMode: responseMode,
		Scopes: scopes, PKCEChallenge: challenge, State: state, Nonce: values.Get("nonce"),
		Prompts: prompts, MaxAge: maxAge,
	}, nil
}

func localAuthorizationError(code ErrorCode, status int) error {
	return &AuthorizationError{Code: code, HTTPStatus: status}
}

func validQueryUTF8(values url.Values) bool {
	for key, entries := range values {
		if !utf8.ValidString(key) {
			return false
		}
		for _, value := range entries {
			if !utf8.ValidString(value) {
				return false
			}
		}
	}
	return true
}

func validOpaqueParameter(value string) bool {
	return len(value) >= 1 && len(value) <= maxOpaqueParameterBytes && utf8.ValidString(value)
}

func parseScope(raw string, allowed []string) ([]string, bool) {
	parts, ok := splitStrictSpaceList(raw)
	if !ok {
		return nil, false
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = true
	}
	result := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, scope := range parts {
		if (scope != "openid" && scope != "profile" && scope != "email") || !allowedSet[scope] {
			return nil, false
		}
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	if !seen["openid"] {
		return nil, false
	}
	sort.Strings(result)
	return result, true
}

func validS256Challenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func parsePrompt(entries []string) (PromptSet, bool) {
	if len(entries) == 0 {
		return PromptSet{}, true
	}
	if len(entries) != 1 {
		return PromptSet{}, false
	}
	parts, ok := splitStrictSpaceList(entries[0])
	if !ok {
		return PromptSet{}, false
	}
	seen := make(map[string]bool, len(parts))
	for _, value := range parts {
		if value != "none" && value != "login" && value != "consent" && value != "create" {
			return PromptSet{}, false
		}
		if seen[value] {
			return PromptSet{}, false
		}
		seen[value] = true
	}
	if (seen["none"] && len(seen) != 1) || (seen["create"] && seen["login"]) {
		return PromptSet{}, false
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return PromptSet{values: values}, true
}

func parseMaxAge(entries []string) (*uint32, bool) {
	if len(entries) == 0 {
		return nil, true
	}
	if len(entries) != 1 {
		return nil, false
	}
	raw := entries[0]
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return nil, false
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return nil, false
		}
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || value > maxAgeSeconds {
		return nil, false
	}
	result := uint32(value)
	return &result, true
}

func splitStrictSpaceList(raw string) ([]string, bool) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\t\r\n") {
		return nil, false
	}
	parts := strings.Split(raw, " ")
	for _, value := range parts {
		if value == "" {
			return nil, false
		}
	}
	return parts, true
}

var reservedAuthorizationResponseParameters = []string{"code", "error", "error_description", "error_uri", "state"}

// BuildAuthorizationRedirect safely merges a protocol response into an already
// registered exact Redirect URI. Existing reserved parameters are removed before
// adding the server response; fragments and non-absolute inputs are rejected.
func BuildAuthorizationRedirect(registered string, response url.Values) (string, error) {
	parsed, err := url.Parse(registered)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", errors.New("registered redirect URI is invalid")
	}
	query := parsed.Query()
	for _, name := range reservedAuthorizationResponseParameters {
		query.Del(name)
	}
	for name, entries := range response {
		if len(entries) != 1 || (name != "code" && name != "error" && name != "state") {
			return "", errors.New("authorization response parameters are invalid")
		}
		query.Set(name, entries[0])
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// BuildAuthorizationSuccessRedirect emits exactly one non-empty opaque Code and
// the optional original State to a previously verified registered URI.
func BuildAuthorizationSuccessRedirect(registered, code, state string) (string, error) {
	if code == "" || len(code) > 256 || strings.ContainsAny(code, "\r\n\t ") {
		return "", errors.New("authorization success response is invalid")
	}
	values := url.Values{"code": {code}}
	if state != "" {
		values.Set("state", state)
	}
	return BuildAuthorizationRedirect(registered, values)
}

// BuildAuthorizationErrorRedirect emits only an allowlisted error and optional
// validated State for a redirect-trusted error.
func BuildAuthorizationErrorRedirect(protocolError *AuthorizationError) (string, error) {
	if protocolError == nil || !protocolError.SafeToRedirect || protocolError.RedirectURI == "" || !validErrorCode(protocolError.Code) {
		return "", errors.New("authorization error is not redirectable")
	}
	values := url.Values{"error": {string(protocolError.Code)}}
	if protocolError.State != "" {
		values.Set("state", protocolError.State)
	}
	return BuildAuthorizationRedirect(protocolError.RedirectURI, values)
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorInvalidRequest, ErrorUnauthorizedClient, ErrorUnsupportedResponseType, ErrorInvalidScope,
		ErrorServerError, ErrorTemporarilyUnavailable, ErrorUnsupportedResponseMode, ErrorLoginRequired,
		ErrorConsentRequired, ErrorInteractionRequired, ErrorAccessDenied, ErrorRequestNotSupported,
		ErrorRequestURINotSupported:
		return true
	default:
		return false
	}
}
