package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/pagination"
	"github.com/oneissuer/oneissuer/internal/session"
)

type pageResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type meResponse struct {
	User      identity.User `json:"user"`
	SessionID uuid.UUID     `json:"session_id"`
}

func (a *applicationHandler) handleMe(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}
	principal, ok := a.requirePrincipal(writer, request)
	if !ok {
		return
	}
	if _, err := a.ensureCSRF(writer, request, &principal); err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, meResponse{User: principal.User, SessionID: principal.SessionID})
}

func (a *applicationHandler) handleMySessions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}
	principal, ok := a.requirePrincipal(writer, request)
	if !ok {
		return
	}
	if _, err := a.ensureCSRF(writer, request, &principal); err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	cursor, limit, err := parsePage(request)
	if err != nil || !queryKeysAllowed(request, "cursor", "limit") {
		writeApplicationError(writer, request, pagination.ErrInvalidCursor)
		return
	}
	items, err := a.sessions.ListMine(request.Context(), principal, cursor, limit)
	if err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	items, next := nextCursor(items, limit, func(item session.Summary) pagination.Cursor {
		return pagination.Cursor{Time: item.CreatedAt, ID: item.ID}
	})
	writeJSON(writer, http.StatusOK, pageResponse[session.Summary]{Items: items, NextCursor: next})
}

func (a *applicationHandler) handleRevokeMySession(writer http.ResponseWriter, request *http.Request, rawID string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodPost)
		return
	}
	target, valid := parseUUID(rawID)
	if !valid {
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	principal, ok := a.requirePrincipalMutation(writer, request)
	if !ok {
		return
	}
	if err := a.sessions.RevokeMine(request.Context(), principal, target, RequestID(request.Context()), a.now().UTC()); err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	if target == principal.SessionID {
		a.cookies.ClearAuthenticated(writer)
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (a *applicationHandler) handleRevokeOtherSessions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodPost)
		return
	}
	principal, ok := a.requirePrincipalMutation(writer, request)
	if !ok {
		return
	}
	count, err := a.sessions.RevokeOthers(request.Context(), principal, RequestID(request.Context()), a.now().UTC())
	if err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]int64{"revoked": count})
}

func (a *applicationHandler) handleAdminMe(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}
	principal, ok := a.requirePrincipal(writer, request)
	if !ok {
		return
	}
	if err := a.admin.Authorize(principal); err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	if _, err := a.ensureCSRF(writer, request, &principal); err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, meResponse{User: principal.User, SessionID: principal.SessionID})
}

type createUserRequest struct {
	Username    string        `json:"username"`
	DisplayName string        `json:"display_name"`
	Email       string        `json:"email"`
	Password    string        `json:"password"`
	Role        identity.Role `json:"role"`
}

type updateUserRequest struct {
	Username    *string          `json:"username"`
	DisplayName *string          `json:"display_name"`
	Email       *string          `json:"email"`
	Status      *identity.Status `json:"status"`
	Role        *identity.Role   `json:"role"`
}

func (a *applicationHandler) handleAdminUsers(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		principal, ok := a.requirePrincipal(writer, request)
		if !ok {
			return
		}
		if _, err := a.ensureCSRF(writer, request, &principal); err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		cursor, limit, err := parsePage(request)
		if err != nil || !queryKeysAllowed(request, "cursor", "limit", "search") {
			writeApplicationError(writer, request, pagination.ErrInvalidCursor)
			return
		}
		items, err := a.admin.ListUsers(request.Context(), principal, request.URL.Query().Get("search"), cursor, limit)
		if err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		items, next := nextCursor(items, limit, func(item identity.User) pagination.Cursor {
			return pagination.Cursor{Time: item.CreatedAt, ID: item.ID}
		})
		writeJSON(writer, http.StatusOK, pageResponse[identity.User]{Items: items, NextCursor: next})
	case http.MethodPost:
		principal, ok := a.requirePrincipalMutation(writer, request)
		if !ok {
			return
		}
		var body createUserRequest
		if err := decodeJSON(writer, request, &body); err != nil {
			writeError(writer, request, http.StatusBadRequest, "invalid_json", "request body is invalid")
			return
		}
		if body.Role == "" {
			body.Role = identity.RoleUser
		}
		user, err := a.admin.CreateUser(request.Context(), principal, identity.CreateInput{
			Username: body.Username, DisplayName: body.DisplayName, Email: body.Email, Password: body.Password,
		}, body.Role, RequestID(request.Context()), a.now().UTC())
		body.Password = ""
		if err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusCreated, user)
	default:
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPost)
	}
}

func (a *applicationHandler) handleAdminUser(writer http.ResponseWriter, request *http.Request, rawID string) {
	id, valid := parseUUID(rawID)
	if !valid {
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	switch request.Method {
	case http.MethodGet:
		principal, ok := a.requirePrincipal(writer, request)
		if !ok {
			return
		}
		value, err := a.admin.GetUser(request.Context(), principal, id)
		if err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, value)
	case http.MethodPatch:
		principal, ok := a.requirePrincipalMutation(writer, request)
		if !ok {
			return
		}
		var body updateUserRequest
		if err := decodeJSON(writer, request, &body); err != nil {
			writeError(writer, request, http.StatusBadRequest, "invalid_json", "request body is invalid")
			return
		}
		value, err := a.admin.UpdateUser(request.Context(), principal, id, identity.UpdateInput{
			Username: body.Username, DisplayName: body.DisplayName, Email: body.Email, Status: body.Status, Role: body.Role,
		}, RequestID(request.Context()), a.now().UTC())
		if err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, value)
	default:
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPatch)
	}
}

func (a *applicationHandler) handleAdminRevokeUserSessions(writer http.ResponseWriter, request *http.Request, rawID string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodPost)
		return
	}
	id, valid := parseUUID(rawID)
	if !valid {
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	principal, ok := a.requirePrincipalMutation(writer, request)
	if !ok {
		return
	}
	count, err := a.admin.RevokeUserSessions(request.Context(), principal, id, RequestID(request.Context()), a.now().UTC())
	if err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]int64{"revoked": count})
}

type createClientRequest struct {
	ClientType          clientdomain.Type `json:"client_type"`
	Name                string            `json:"name"`
	Description         string            `json:"description"`
	LogoURI             string            `json:"logo_uri"`
	RegistrationEnabled bool              `json:"registration_enabled"`
	RedirectURIs        []string          `json:"redirect_uris"`
	LogoutURIs          []string          `json:"logout_uris"`
	Scopes              []string          `json:"scopes"`
}

type updateClientRequest struct {
	Name                *string              `json:"name"`
	Description         *string              `json:"description"`
	LogoURI             *string              `json:"logo_uri"`
	Status              *clientdomain.Status `json:"status"`
	RegistrationEnabled *bool                `json:"registration_enabled"`
	RedirectURIs        *[]string            `json:"redirect_uris"`
	LogoutURIs          *[]string            `json:"logout_uris"`
	Scopes              *[]string            `json:"scopes"`
}

func (a *applicationHandler) handleAdminClients(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		principal, ok := a.requirePrincipal(writer, request)
		if !ok {
			return
		}
		if _, err := a.ensureCSRF(writer, request, &principal); err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		cursor, limit, err := parsePage(request)
		if err != nil || !queryKeysAllowed(request, "cursor", "limit") {
			writeApplicationError(writer, request, pagination.ErrInvalidCursor)
			return
		}
		items, err := a.admin.ListClients(request.Context(), principal, cursor, limit)
		if err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		items, next := nextCursor(items, limit, func(item clientdomain.Client) pagination.Cursor {
			return pagination.Cursor{Time: item.CreatedAt, ID: item.ID}
		})
		writeJSON(writer, http.StatusOK, pageResponse[clientdomain.Client]{Items: items, NextCursor: next})
	case http.MethodPost:
		principal, ok := a.requirePrincipalMutation(writer, request)
		if !ok {
			return
		}
		var body createClientRequest
		if err := decodeJSON(writer, request, &body); err != nil {
			writeError(writer, request, http.StatusBadRequest, "invalid_json", "request body is invalid")
			return
		}
		created, err := a.admin.CreateClient(request.Context(), principal, clientdomain.CreateInput{
			Type: body.ClientType, Name: body.Name, Description: body.Description, LogoURI: body.LogoURI,
			RegistrationEnabled: body.RegistrationEnabled, RedirectURIs: body.RedirectURIs,
			LogoutURIs: body.LogoutURIs, Scopes: body.Scopes,
		}, RequestID(request.Context()), a.now().UTC())
		if err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeJSON(writer, http.StatusCreated, created)
	default:
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPost)
	}
}

func (a *applicationHandler) handleAdminClient(writer http.ResponseWriter, request *http.Request, rawID string) {
	id, valid := parseUUID(rawID)
	if !valid {
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	switch request.Method {
	case http.MethodGet:
		principal, ok := a.requirePrincipal(writer, request)
		if !ok {
			return
		}
		value, err := a.admin.GetClient(request.Context(), principal, id)
		if err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, value)
	case http.MethodPatch:
		principal, ok := a.requirePrincipalMutation(writer, request)
		if !ok {
			return
		}
		var body updateClientRequest
		if err := decodeJSON(writer, request, &body); err != nil {
			writeError(writer, request, http.StatusBadRequest, "invalid_json", "request body is invalid")
			return
		}
		value, err := a.admin.UpdateClient(request.Context(), principal, id, clientdomain.UpdateInput{
			Name: body.Name, Description: body.Description, LogoURI: body.LogoURI, Status: body.Status,
			RegistrationEnabled: body.RegistrationEnabled, RedirectURIs: body.RedirectURIs,
			LogoutURIs: body.LogoutURIs, Scopes: body.Scopes,
		}, RequestID(request.Context()), a.now().UTC())
		if err != nil {
			writeApplicationError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, value)
	default:
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPatch)
	}
}

func (a *applicationHandler) handleAdminRotateClientSecret(writer http.ResponseWriter, request *http.Request, rawID string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodPost)
		return
	}
	id, valid := parseUUID(rawID)
	if !valid {
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	principal, ok := a.requirePrincipalMutation(writer, request)
	if !ok {
		return
	}
	secret, err := a.admin.RotateClientSecret(request.Context(), principal, id, RequestID(request.Context()), a.now().UTC())
	if err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]string{"client_secret": secret})
}

func (a *applicationHandler) handleAdminSessions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}
	principal, ok := a.requirePrincipal(writer, request)
	if !ok {
		return
	}
	if _, err := a.ensureCSRF(writer, request, &principal); err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	cursor, limit, err := parsePage(request)
	if err != nil || !queryKeysAllowed(request, "cursor", "limit") {
		writeApplicationError(writer, request, pagination.ErrInvalidCursor)
		return
	}
	items, err := a.admin.ListSessions(request.Context(), principal, cursor, limit)
	if err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	items, next := nextCursor(items, limit, func(item session.Summary) pagination.Cursor {
		return pagination.Cursor{Time: item.CreatedAt, ID: item.ID}
	})
	writeJSON(writer, http.StatusOK, pageResponse[session.Summary]{Items: items, NextCursor: next})
}

func (a *applicationHandler) handleAdminRevokeSession(writer http.ResponseWriter, request *http.Request, rawID string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodPost)
		return
	}
	id, valid := parseUUID(rawID)
	if !valid {
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	principal, ok := a.requirePrincipalMutation(writer, request)
	if !ok {
		return
	}
	if err := a.admin.RevokeSession(request.Context(), principal, id, RequestID(request.Context()), a.now().UTC()); err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	if id == principal.SessionID {
		a.cookies.ClearAuthenticated(writer)
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (a *applicationHandler) handleAdminAudit(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}
	principal, ok := a.requirePrincipal(writer, request)
	if !ok {
		return
	}
	if _, err := a.ensureCSRF(writer, request, &principal); err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	cursor, limit, err := parsePage(request)
	if err != nil || !queryKeysAllowed(request, "cursor", "limit", "event_type") {
		writeApplicationError(writer, request, pagination.ErrInvalidCursor)
		return
	}
	items, err := a.admin.ListAudit(request.Context(), principal, request.URL.Query().Get("event_type"), cursor, limit)
	if err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	items, next := nextCursor(items, limit, func(item audit.Event) pagination.Cursor {
		return pagination.Cursor{Time: item.OccurredAt, ID: item.ID}
	})
	writeJSON(writer, http.StatusOK, pageResponse[audit.Event]{Items: items, NextCursor: next})
}

func (a *applicationHandler) requirePrincipal(writer http.ResponseWriter, request *http.Request) (session.Principal, bool) {
	principal, err := a.authenticate(request)
	if err != nil {
		writeApplicationError(writer, request, session.ErrUnauthenticated)
		return session.Principal{}, false
	}
	return principal, true
}

func (a *applicationHandler) requirePrincipalMutation(writer http.ResponseWriter, request *http.Request) (session.Principal, bool) {
	principal, ok := a.requirePrincipal(writer, request)
	if !ok {
		return session.Principal{}, false
	}
	header := csrfHeader(request)
	cookie := a.cookies.CSRFToken(request)
	if header == "" || cookie == "" || !sameClearToken(header, cookie) || !a.requireStateChange(writer, request, principal, header) {
		if header == "" || cookie == "" || !sameClearToken(header, cookie) {
			writeError(writer, request, http.StatusForbidden, "csrf_failed", "CSRF validation failed")
		}
		return session.Principal{}, false
	}
	return principal, true
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" {
		return errors.New("unsupported JSON content type")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxAuthBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func queryKeysAllowed(request *http.Request, allowed ...string) bool {
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	for key, values := range request.URL.Query() {
		if !set[key] || len(values) != 1 {
			return false
		}
	}
	return true
}
