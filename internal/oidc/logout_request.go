package oidc

import (
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	maxLogoutHintBytes     = 8 << 10
	maxLogoutClientIDBytes = 128
	maxLogoutURIBytes      = 2048
	maxLogoutOpaqueBytes   = 1024
)

// ErrInvalidLogoutRequest identifies a malformed RP-Initiated Logout request.
var ErrInvalidLogoutRequest = errors.New("RP logout request is invalid")

// LogoutRequest is the strict standard request projection. Clear values remain
// in the protocol-to-service frame and must never enter logs or errors.
type LogoutRequest struct {
	IDTokenHint           string
	ClientID              string
	LogoutHint            string
	PostLogoutRedirectURI string
	State                 string
	UILocales             string
}

// ParseLogoutRequest validates single-value fields and bounded UTF-8. Hint/URI
// cryptographic and registration policy belongs to internal/logout.
func ParseLogoutRequest(values url.Values) (LogoutRequest, error) {
	allowed := map[string]int{
		"id_token_hint": maxLogoutHintBytes, "client_id": maxLogoutClientIDBytes,
		"logout_hint": maxLogoutOpaqueBytes, "post_logout_redirect_uri": maxLogoutURIBytes,
		"state": maxLogoutOpaqueBytes, "ui_locales": maxLogoutOpaqueBytes,
	}
	for name, entries := range values {
		maximum, exists := allowed[name]
		if !exists || len(entries) != 1 {
			return LogoutRequest{}, ErrInvalidLogoutRequest
		}
		value := entries[0]
		if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
			return LogoutRequest{}, ErrInvalidLogoutRequest
		}
	}
	return LogoutRequest{
		IDTokenHint: values.Get("id_token_hint"), ClientID: values.Get("client_id"),
		LogoutHint: values.Get("logout_hint"), PostLogoutRedirectURI: values.Get("post_logout_redirect_uri"),
		State: values.Get("state"), UILocales: values.Get("ui_locales"),
	}, nil
}
