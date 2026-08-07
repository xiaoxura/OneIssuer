package httpserver

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authn"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/identity"
	logoutdomain "github.com/oneissuer/oneissuer/internal/logout"
	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/pagination"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/token"
)

const (
	maxAuthBodyBytes        = 64 << 10
	defaultOperationTimeout = 10 * time.Second
)

//go:embed templates/*.html
var templateFiles embed.FS

// ApplicationOptions supplies browser and JSON API dependencies.
type ApplicationOptions struct {
	Authn          *authn.Service
	Sessions       *session.Service
	Admin          *admin.Service
	Clients        *clientdomain.Service
	Transactions   *authflow.Service
	Consents       *consent.Service
	Authorization  *authorization.Service
	Tokens         ProtocolTokenService
	Cookies        session.CookieManager
	Issuer         *url.URL
	PublicKeys     PublicKeySet
	AuthRateLimit  AuthenticationRateLimitConfig
	Logout         *logoutdomain.Service
	LogoutCookies  logoutdomain.CookieManager
	OAuthRateLimit AuthenticationRateLimitConfig
	Now            func() time.Time
}

// ProtocolTokenService is the narrow HTTP boundary for Code exchange and
// UserInfo. It deliberately exposes neither signing keys nor persistence.
type ProtocolTokenService interface {
	Exchange(context.Context, token.ExchangeInput) (token.Response, error)
	Refresh(context.Context, token.RefreshInput) (token.Response, error)
	Revoke(context.Context, token.RevocationInput) error
	Introspect(context.Context, token.IntrospectionInput) (token.IntrospectionResponse, error)
	UserInfoForAccessToken(context.Context, string, time.Time) (token.UserInfo, error)
}

// PublicKeySet is the intentionally narrow HTTP view of the immutable key
// store. It cannot expose or serialize active private key material.
type PublicKeySet interface {
	PublicJWKS() []byte
	ETag() string
}

type applicationHandler struct {
	authn         *authn.Service
	sessions      *session.Service
	admin         *admin.Service
	clients       *clientdomain.Service
	tokenClients  oidc.TokenClientResolver
	transactions  *authflow.Service
	consents      *consent.Service
	authorization *authorization.Service
	logout        *logoutdomain.Service
	logoutCookies logoutdomain.CookieManager
	tokens        ProtocolTokenService
	cookies       session.CookieManager
	issuer        *url.URL
	publicKeys    PublicKeySet
	metadata      []byte
	now           func() time.Time
	authLimiter   *authenticationRateLimiter
	oauthLimiter  *authenticationRateLimiter
	templates     *template.Template
}

// NewApplicationHandler creates the hosted browser, protocol, and management router.
func NewApplicationHandler(options ApplicationOptions) (http.Handler, error) {
	if options.Authn == nil || options.Sessions == nil || options.Admin == nil || options.Issuer == nil {
		return nil, errors.New("application HTTP dependencies are incomplete")
	}
	templates, err := template.ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		return nil, errors.New("embedded authentication templates are invalid")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	metadataOptions := []oidc.MetadataOption{}
	if options.Logout != nil {
		metadataOptions = append(metadataOptions, oidc.WithEndSessionEndpoint())
	}
	metadata, err := oidc.BuildProviderMetadata(options.Issuer, metadataOptions...)
	if err != nil {
		return nil, errors.New("OIDC provider metadata configuration is invalid")
	}
	encodedMetadata, err := oidc.MarshalProviderMetadata(metadata)
	if err != nil {
		return nil, errors.New("OIDC provider metadata could not be initialized")
	}
	return &applicationHandler{
		authn: options.Authn, sessions: options.Sessions, admin: options.Admin,
		clients: options.Clients, tokenClients: options.Clients, transactions: options.Transactions, consents: options.Consents, authorization: options.Authorization, tokens: options.Tokens,
		logout: options.Logout, logoutCookies: options.LogoutCookies,
		cookies: options.Cookies, issuer: options.Issuer, publicKeys: options.PublicKeys, metadata: encodedMetadata, now: options.Now, templates: templates,
		authLimiter:  newAuthenticationRateLimiter(options.AuthRateLimit, options.Now().UTC()),
		oauthLimiter: newAuthenticationRateLimiter(options.OAuthRateLimit, options.Now().UTC()),
	}, nil
}

func (a *applicationHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if a.issuer != nil {
		// Keep the configured Issuer explicit in addition to 'self'. Some
		// browsers evaluate form-action across a top-level cross-origin redirect
		// chain using the serialized origin rather than the self keyword alone.
		setFormActionPolicy(writer.Header(), a.issuer.String())
	}
	if a.oauthLifecycleRateLimited(request) {
		a.writeOAuthRateLimitResponse(writer, request)
		return
	}
	if a.authenticationRateLimited(request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Retry-After", "60")
		if request.URL.Path == oidc.AuthorizePath {
			writeError(writer, request, http.StatusTooManyRequests, "temporarily_unavailable", "authentication request rate limit exceeded")
		} else {
			a.renderErrorPage(writer, request, http.StatusTooManyRequests, "temporarily_unavailable")
		}
		return
	}
	switch request.URL.Path {
	case oidc.AuthorizePath, oidc.AuthorizeContinuePath:
		if !a.oidcAuthorizationReady() {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		if request.URL.Path == oidc.AuthorizePath {
			a.handleAuthorize(writer, request)
		} else {
			a.handleAuthorizeContinuation(writer, request)
		}
	case "/consent":
		if !a.oidcAuthorizationReady() {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		if request.Method == http.MethodGet {
			a.getConsent(writer, request)
			return
		}
		if request.Method == http.MethodPost {
			a.postConsent(writer, request)
			return
		}
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPost)
	case oidc.TokenPath:
		if a.tokenClients == nil || a.tokens == nil {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		a.handleToken(writer, request)
	case oidc.UserInfoPath:
		if a.tokens == nil {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		a.handleUserInfo(writer, request)
	case oidc.RevocationPath:
		if a.tokenClients == nil || a.tokens == nil {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		a.handleRevocation(writer, request)
	case oidc.IntrospectionPath:
		if a.tokenClients == nil || a.tokens == nil {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		a.handleIntrospection(writer, request)
	case oidc.LogoutPath:
		if a.logout == nil {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		a.handleRPLogoutRequest(writer, request)
	case oidc.LogoutConfirmPath:
		if a.logout == nil {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		a.handleRPLogoutConfirmation(writer, request)
	case oidc.DiscoveryPath:
		if !a.oidcProviderReady() {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		a.handleDiscovery(writer, request)
	case oidc.JWKSPath:
		if a.publicKeys == nil {
			writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
			return
		}
		a.handleJWKS(writer, request)
	case "/login":
		if request.Method == http.MethodGet {
			a.getAuthForm(writer, request, authn.BeginLogin)
			return
		}
		if request.Method == http.MethodPost {
			a.postLogin(writer, request)
			return
		}
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPost)
	case "/register":
		if request.Method == http.MethodGet {
			a.getAuthForm(writer, request, authn.BeginRegister)
			return
		}
		if request.Method == http.MethodPost {
			a.postRegister(writer, request)
			return
		}
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPost)
	case "/logout":
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, request, http.MethodPost)
			return
		}
		a.postLogout(writer, request)
	case "/auth/complete":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, request, http.MethodGet)
			return
		}
		a.getComplete(writer, request)
	case "/api/v1/me":
		a.handleMe(writer, request)
	case "/api/v1/me/sessions":
		a.handleMySessions(writer, request)
	case "/api/v1/me/sessions/revoke-others":
		a.handleRevokeOtherSessions(writer, request)
	case "/api/v1/me/grants":
		a.handleMyGrants(writer, request)
	case "/api/v1/me/grants/revoke":
		a.handleRevokeMyGrant(writer, request)
	case "/api/admin/v1/me":
		a.handleAdminMe(writer, request)
	case "/api/admin/v1/users":
		a.handleAdminUsers(writer, request)
	case "/api/admin/v1/clients":
		a.handleAdminClients(writer, request)
	case "/api/admin/v1/sessions":
		a.handleAdminSessions(writer, request)
	case "/api/admin/v1/audit-events":
		a.handleAdminAudit(writer, request)
	default:
		if a.serveDynamic(writer, request) {
			return
		}
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
	}
}

func (a *applicationHandler) writeOAuthRateLimitResponse(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("Retry-After", "1")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	if request.URL.Path == oidc.LogoutPath {
		a.renderErrorPage(writer, request, http.StatusTooManyRequests, "temporarily_unavailable")
		return
	}
	setTokenResponseHeaders(writer.Header())
	if request.URL.Path == oidc.UserInfoPath {
		writeBearerError(writer, "temporarily_unavailable", http.StatusTooManyRequests)
		return
	}
	writeOAuthError(writer, &oidc.TokenError{Code: "temporarily_unavailable", HTTPStatus: http.StatusTooManyRequests})
}

func (a *applicationHandler) oauthLifecycleRateLimited(request *http.Request) bool {
	if a.oauthLimiter == nil {
		return false
	}
	var sensitive bool
	switch request.URL.Path {
	case oidc.TokenPath, oidc.RevocationPath, oidc.IntrospectionPath:
		sensitive = request.Method == http.MethodPost
	case oidc.UserInfoPath:
		sensitive = request.Method == http.MethodGet || request.Method == http.MethodPost
	case oidc.LogoutPath:
		sensitive = request.Method == http.MethodGet || request.Method == http.MethodPost
	}
	return sensitive && !a.oauthLimiter.allow(requestClientIP(request), a.now().UTC())
}

func (a *applicationHandler) oauthClientRateLimited(clientID uuid.UUID) bool {
	return a.oauthLimiter != nil && !a.oauthLimiter.allowClient(clientID, a.now().UTC())
}

func (a *applicationHandler) authenticationRateLimited(request *http.Request) bool {
	if a.authLimiter == nil {
		return false
	}
	sensitive := (request.URL.Path == oidc.AuthorizePath && request.Method == http.MethodGet) ||
		((request.URL.Path == "/login" || request.URL.Path == "/register") &&
			(request.Method == http.MethodGet || request.Method == http.MethodPost))
	return sensitive && !a.authLimiter.allow(requestClientIP(request), a.now().UTC())
}

func (a *applicationHandler) oidcAuthorizationReady() bool {
	return a.clients != nil && a.transactions != nil && a.consents != nil && a.authorization != nil
}

func (a *applicationHandler) oidcProviderReady() bool {
	return a.oidcAuthorizationReady() && a.tokenClients != nil && a.tokens != nil && a.publicKeys != nil && len(a.metadata) != 0
}

func (a *applicationHandler) serveDynamic(writer http.ResponseWriter, request *http.Request) bool {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) == 6 && strings.Join(parts[:4], "/") == "api/v1/me/sessions" && parts[5] == "revoke" {
		a.handleRevokeMySession(writer, request, parts[4])
		return true
	}
	if len(parts) >= 5 && strings.Join(parts[:4], "/") == "api/admin/v1/users" {
		if len(parts) == 5 {
			a.handleAdminUser(writer, request, parts[4])
			return true
		}
		if len(parts) == 6 && parts[5] == "revoke-sessions" {
			a.handleAdminRevokeUserSessions(writer, request, parts[4])
			return true
		}
	}
	if len(parts) >= 5 && strings.Join(parts[:4], "/") == "api/admin/v1/clients" {
		if len(parts) == 5 {
			a.handleAdminClient(writer, request, parts[4])
			return true
		}
		if len(parts) == 7 && parts[5] == "secrets" && parts[6] == "rotate" {
			a.handleAdminRotateClientSecret(writer, request, parts[4])
			return true
		}
	}
	if len(parts) == 6 && strings.Join(parts[:4], "/") == "api/admin/v1/sessions" && parts[5] == "revoke" {
		a.handleAdminRevokeSession(writer, request, parts[4])
		return true
	}
	return false
}

func methodNotAllowed(writer http.ResponseWriter, request *http.Request, methods ...string) {
	writer.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(writer, request, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func (a *applicationHandler) authenticate(request *http.Request) (session.Principal, error) {
	return a.sessions.Authenticate(request.Context(), a.cookies.SessionToken(request), a.now().UTC())
}

func operationContext(request *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(request.Context(), defaultOperationTimeout)
}

func (a *applicationHandler) requireStateChange(writer http.ResponseWriter, request *http.Request, principal session.Principal, token string) bool {
	if !a.sameOrigin(request) {
		writeError(writer, request, http.StatusForbidden, "csrf_failed", "request origin was rejected")
		return false
	}
	if err := a.sessions.ValidateCSRF(principal, token, a.now().UTC()); err != nil {
		writeError(writer, request, http.StatusForbidden, "csrf_failed", "CSRF validation failed")
		return false
	}
	return true
}

func (a *applicationHandler) sameOrigin(request *http.Request) bool {
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		referer := strings.TrimSpace(request.Header.Get("Referer"))
		if referer == "" {
			return true // CSRF token remains the primary control for non-browser clients.
		}
		parsed, err := url.Parse(referer)
		if err != nil {
			return false
		}
		origin = parsed.Scheme + "://" + parsed.Host
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, a.issuer.Scheme) && strings.EqualFold(parsed.Host, a.issuer.Host)
}

func (a *applicationHandler) ensureCSRF(writer http.ResponseWriter, request *http.Request, principal *session.Principal) (string, error) {
	presented := a.cookies.CSRFToken(request)
	token, rotated, err := a.sessions.EnsureCSRF(request.Context(), principal, presented, a.now().UTC())
	if err != nil {
		return "", err
	}
	if rotated {
		a.cookies.SetCSRF(writer, token)
	}
	writer.Header().Set("X-CSRF-Token", token)
	return token, nil
}

func requestClientIP(request *http.Request) netip.Addr {
	proxy := RequestProxyInfo(request.Context())
	if proxy.ClientIP.IsValid() {
		return proxy.ClientIP
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	address, _ := netip.ParseAddr(host)
	return address
}

func parseUUID(raw string) (uuid.UUID, bool) {
	value, err := uuid.Parse(raw)
	return value, err == nil && value != uuid.Nil
}

func parsePage(request *http.Request) (pagination.Cursor, int, error) {
	cursor, err := pagination.Decode(request.URL.Query().Get("cursor"))
	if err != nil {
		return pagination.Cursor{}, 0, err
	}
	limit := 20
	if raw := request.URL.Query().Get("limit"); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < 1 || value > 100 {
			return pagination.Cursor{}, 0, pagination.ErrInvalidCursor
		}
		limit = value
	}
	return cursor, limit, nil
}

func nextCursor[T any](items []T, limit int, position func(T) pagination.Cursor) ([]T, string) {
	if len(items) <= limit {
		return items, ""
	}
	items = items[:limit]
	return items, pagination.Encode(position(items[len(items)-1]))
}

func csrfHeader(request *http.Request) string {
	return strings.TrimSpace(request.Header.Get("X-CSRF-Token"))
}

func sameClearToken(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func authErrorStatus(err error) (int, string, string) {
	switch {
	case errors.Is(err, session.ErrUnauthenticated):
		return http.StatusUnauthorized, "authentication_required", "authentication required"
	case errors.Is(err, session.ErrInvalidCSRF):
		return http.StatusForbidden, "csrf_failed", "CSRF validation failed"
	case errors.Is(err, admin.ErrForbidden):
		return http.StatusForbidden, "forbidden", "administrator permission required"
	case errors.Is(err, admin.ErrRecentAuth):
		return http.StatusForbidden, "recent_authentication_required", "recent authentication required"
	case errors.Is(err, identity.ErrNotFound), errors.Is(err, clientdomain.ErrNotFound), errors.Is(err, session.ErrNotFound), errors.Is(err, consent.ErrNotFound):
		return http.StatusNotFound, "not_found", "resource not found"
	case errors.Is(err, identity.ErrDuplicate), errors.Is(err, identity.ErrConflict), errors.Is(err, clientdomain.ErrConflict):
		return http.StatusConflict, "conflict", "resource conflicts with existing state"
	case errors.Is(err, identity.ErrLastAdmin):
		return http.StatusConflict, "last_admin_protected", "the last active administrator is protected"
	case errors.Is(err, identity.ErrInvalidInput), errors.Is(err, clientdomain.ErrInvalid), errors.Is(err, clientdomain.ErrPublicSecret),
		errors.Is(err, admin.ErrInvalidFilter), errors.Is(err, pagination.ErrInvalidCursor), errors.Is(err, consent.ErrInvalid):
		return http.StatusUnprocessableEntity, "invalid_input", "request input is invalid"
	case errors.Is(err, identity.ErrHashBusy):
		return http.StatusTooManyRequests, "temporarily_unavailable", "authentication capacity is temporarily unavailable"
	case errors.Is(err, authn.ErrRegistrationDisabled):
		return http.StatusForbidden, "registration_disabled", "registration is disabled"
	case errors.Is(err, authn.ErrInvalidFlow), errors.Is(err, authflow.ErrExpired), errors.Is(err, authflow.ErrConsumed):
		return http.StatusBadRequest, "invalid_authentication_flow", "authentication flow is invalid"
	default:
		return http.StatusInternalServerError, "internal_error", "internal server error"
	}
}

func writeApplicationError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message := authErrorStatus(err)
	if status == http.StatusTooManyRequests {
		writer.Header().Set("Retry-After", "1")
	}
	writeError(writer, request, status, code, message)
}
