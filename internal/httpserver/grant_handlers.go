package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/oneissuer/oneissuer/internal/consent"
)

const maxGrantMutationBodyBytes = 8 << 10

// handleMyGrants exposes only owner-safe Grant projections. Its cursor is
// deliberately independent from the UUID-bearing administrative cursor.
func (a *applicationHandler) handleMyGrants(writer http.ResponseWriter, request *http.Request) {
	if a.consents == nil {
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
		return
	}
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
	cursor, limit, err := parseGrantPage(request)
	if err != nil {
		writeApplicationError(writer, request, consent.ErrInvalid)
		return
	}
	page, err := a.consents.ListMine(request.Context(), principal.User.ID, cursor, limit, a.now().UTC())
	if err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, page)
}

// handleRevokeMyGrant accepts exactly one public client_id in a strict JSON
// object. User and internal Grant identifiers never form a browser input.
func (a *applicationHandler) handleRevokeMyGrant(writer http.ResponseWriter, request *http.Request) {
	if a.consents == nil {
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodPost)
		return
	}
	if request.URL.RawQuery != "" {
		writeError(writer, request, http.StatusBadRequest, "invalid_json", "request body is invalid")
		return
	}
	principal, ok := a.requirePrincipalMutation(writer, request)
	if !ok {
		return
	}
	publicClientID, err := decodeGrantRevokeJSON(writer, request)
	if err != nil {
		writeError(writer, request, http.StatusBadRequest, "invalid_json", "request body is invalid")
		return
	}
	grant, err := a.consents.RevokeMine(
		request.Context(), principal.User.ID, publicClientID,
		RequestID(request.Context()), a.now().UTC(),
	)
	if err != nil {
		writeApplicationError(writer, request, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, grant)
}

func parseGrantPage(request *http.Request) (string, int, error) {
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return "", 0, consent.ErrInvalid
	}
	for key, entries := range values {
		if (key != "cursor" && key != "limit") || len(entries) != 1 {
			return "", 0, consent.ErrInvalid
		}
	}
	rawCursor := values.Get("cursor")
	if _, err := consent.DecodeGrantCursor(rawCursor); err != nil {
		return "", 0, consent.ErrInvalid
	}
	limit := 20
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 || strconv.Itoa(parsed) != raw {
			return "", 0, consent.ErrInvalid
		}
		limit = parsed
	}
	return rawCursor, limit, nil
}

func decodeGrantRevokeJSON(writer http.ResponseWriter, request *http.Request) (string, error) {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" {
		return "", errors.New("unsupported JSON content type")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxGrantMutationBodyBytes)
	decoder := json.NewDecoder(request.Body)

	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", errors.New("grant revoke body is not an object")
	}
	var clientID string
	seen := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil || key != "client_id" || seen {
			return "", errors.New("grant revoke body has an unexpected or duplicate field")
		}
		if err := decoder.Decode(&clientID); err != nil {
			return "", errors.New("grant revoke client identifier is invalid")
		}
		seen = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seen {
		return "", errors.New("grant revoke body is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return "", errors.New("grant revoke body has trailing data")
	}
	return clientID, nil
}
