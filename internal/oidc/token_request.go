package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/ory/fosite"
)

// TokenError is a value-free OAuth Token Endpoint error. Error() never embeds
// Client ID, Code, redirect URI, verifier, Authorization Header, or form data.
type TokenError struct {
	Code           string
	HTTPStatus     int
	BasicChallenge bool
}

func (e *TokenError) Error() string {
	if e == nil || e.Code == "" {
		return "OAuth token request failed"
	}
	return "OAuth token request failed: " + e.Code
}

// VerifiedTokenRequest contains strict form/authentication output. Clear Code
// is replaced with its domain-separated digest before leaving the parser.
type VerifiedTokenRequest struct {
	Client       clientdomain.Client
	CodeHash     []byte
	RedirectURI  string
	CodeVerifier string
}

// TokenClientResolver delegates registry and secret authority to the frozen
// Client service instead of exposing hashes through a protocol store.
type TokenClientResolver interface {
	ResolveActive(context.Context, string) (clientdomain.Client, error)
	ValidateSecret(context.Context, string, string) (clientdomain.Client, error)
}

// ParseTokenRequest rejects duplicate security parameters and authentication
// channel mixing before returning a phase-three Code Grant request.
func ParseTokenRequest(ctx context.Context, form url.Values, header http.Header, clients TokenClientResolver) (VerifiedTokenRequest, error) {
	if clients == nil || !validTokenFormUTF8(form) {
		return VerifiedTokenRequest{}, tokenError(fosite.ErrInvalidRequest, false)
	}
	for _, parameter := range []string{"grant_type", "code", "redirect_uri", "code_verifier"} {
		if len(form[parameter]) != 1 || form.Get(parameter) == "" {
			return VerifiedTokenRequest{}, tokenError(fosite.ErrInvalidRequest, false)
		}
	}
	for _, parameter := range []string{"client_id", "client_secret", "scope"} {
		if len(form[parameter]) > 1 {
			return VerifiedTokenRequest{}, tokenError(fosite.ErrInvalidRequest, false)
		}
	}
	if form.Get("grant_type") != "authorization_code" {
		return VerifiedTokenRequest{}, tokenError(fosite.ErrUnsupportedGrantType, false)
	}
	if len(form["client_secret"]) != 0 {
		return VerifiedTokenRequest{}, tokenError(fosite.ErrInvalidClient, len(header.Values("Authorization")) != 0)
	}

	clientValue, challenged, err := authenticateTokenClient(ctx, form, header, clients)
	if err != nil {
		return VerifiedTokenRequest{}, tokenError(fosite.ErrInvalidClient, challenged)
	}
	protocolClient := newFositeClient(clientValue)
	if !protocolClient.GetGrantTypes().Has("authorization_code") || !protocolClient.GetResponseTypes().Has("code") {
		return VerifiedTokenRequest{}, tokenError(fosite.ErrInvalidClient, challenged)
	}
	codeHash, err := authorization.DigestPresentedCode(form.Get("code"))
	if err != nil || authorization.ValidateVerifier(form.Get("code_verifier")) != nil {
		return VerifiedTokenRequest{}, tokenError(fosite.ErrInvalidGrant, false)
	}
	return VerifiedTokenRequest{
		Client: clientValue, CodeHash: codeHash, RedirectURI: form.Get("redirect_uri"), CodeVerifier: form.Get("code_verifier"),
	}, nil
}

func authenticateTokenClient(ctx context.Context, form url.Values, header http.Header, clients TokenClientResolver) (clientdomain.Client, bool, error) {
	authorizationHeaders := header.Values("Authorization")
	if len(authorizationHeaders) > 1 {
		return clientdomain.Client{}, true, clientdomain.ErrNotFound
	}
	if len(authorizationHeaders) == 1 {
		if len(form["client_id"]) != 0 {
			return clientdomain.Client{}, true, clientdomain.ErrNotFound
		}
		clientID, secret, err := parseStrictBasic(authorizationHeaders[0])
		if err != nil {
			return clientdomain.Client{}, true, clientdomain.ErrNotFound
		}
		value, err := clients.ValidateSecret(ctx, clientID, secret)
		if err != nil || value.Type != clientdomain.TypeConfidential || value.TokenEndpointAuthMethod != clientdomain.AuthMethodClientSecretBasic {
			return clientdomain.Client{}, true, clientdomain.ErrNotFound
		}
		return value, true, nil
	}
	if len(form["client_id"]) != 1 || form.Get("client_id") == "" {
		return clientdomain.Client{}, false, clientdomain.ErrNotFound
	}
	value, err := clients.ResolveActive(ctx, form.Get("client_id"))
	if err != nil || value.Type != clientdomain.TypePublic || value.TokenEndpointAuthMethod != clientdomain.AuthMethodNone {
		return clientdomain.Client{}, value.Type == clientdomain.TypeConfidential, clientdomain.ErrNotFound
	}
	return value, false, nil
}

func parseStrictBasic(value string) (string, string, error) {
	if value == "" || strings.ContainsAny(value, "\r\n\t,") {
		return "", "", errors.New("invalid Basic authorization")
	}
	space := strings.IndexByte(value, ' ')
	if space <= 0 || !strings.EqualFold(value[:space], "Basic") || space+1 >= len(value) || strings.Contains(value[space+1:], " ") {
		return "", "", errors.New("invalid Basic authorization")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value[space+1:])
	if err != nil || !utf8.Valid(decoded) || strings.Count(string(decoded), ":") != 1 {
		return "", "", errors.New("invalid Basic authorization")
	}
	encodedID, encodedSecret, _ := strings.Cut(string(decoded), ":")
	clientID, err := url.QueryUnescape(encodedID)
	if err != nil {
		return "", "", errors.New("invalid Basic client identifier")
	}
	secret, err := url.QueryUnescape(encodedSecret)
	if err != nil || clientID == "" || secret == "" || !utf8.ValidString(clientID) || !utf8.ValidString(secret) {
		return "", "", errors.New("invalid Basic credentials")
	}
	return clientID, secret, nil
}

func validTokenFormUTF8(form url.Values) bool {
	for key, values := range form {
		if !utf8.ValidString(key) || strings.ContainsRune(key, '\x00') {
			return false
		}
		for _, value := range values {
			if !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
				return false
			}
		}
	}
	return true
}

func tokenError(template *fosite.RFC6749Error, basic bool) *TokenError {
	if template == nil {
		return &TokenError{Code: "server_error", HTTPStatus: http.StatusInternalServerError}
	}
	return &TokenError{Code: template.ErrorField, HTTPStatus: template.CodeField, BasicChallenge: basic}
}
