// Package main implements the deliberately minimal OneIssuer OIDC
// interoperability example Relying Party.
package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

type exampleConfig struct {
	Name                  string
	Addr                  string
	Issuer                *url.URL
	ProviderBackchannel   *url.URL
	ClientID              string
	ClientSecret          string
	RedirectURI           string
	PostLogoutRedirectURI string
	Scopes                []string
	CookieName            string
	CookieSecure          bool
}

func loadExampleConfig() (exampleConfig, error) {
	issuer, err := parseOrigin(os.Getenv("EXAMPLE_ISSUER"))
	if err != nil {
		return exampleConfig{}, fmt.Errorf("EXAMPLE_ISSUER: %w", err)
	}
	var backchannel *url.URL
	if raw := os.Getenv("EXAMPLE_PROVIDER_BACKCHANNEL"); raw != "" {
		backchannel, err = parseOrigin(raw)
		if err != nil {
			return exampleConfig{}, fmt.Errorf("EXAMPLE_PROVIDER_BACKCHANNEL: %w", err)
		}
	}
	redirect := os.Getenv("EXAMPLE_REDIRECT_URI")
	redirectURL, err := url.Parse(redirect)
	if err != nil || !redirectURL.IsAbs() || redirectURL.Host == "" || redirectURL.User != nil || redirectURL.Opaque != "" ||
		redirectURL.RawPath != "" || redirectURL.Fragment != "" || redirectURL.RawQuery != "" || redirectURL.ForceQuery {
		return exampleConfig{}, errors.New("EXAMPLE_REDIRECT_URI must be an absolute URL without userinfo, query, or fragment")
	}
	if redirectURL.Scheme != "https" && (redirectURL.Scheme != "http" || !isLoopbackHost(redirectURL.Hostname())) {
		return exampleConfig{}, errors.New("EXAMPLE_REDIRECT_URI must use HTTPS except on loopback")
	}
	postLogoutRedirect := os.Getenv("EXAMPLE_POST_LOGOUT_REDIRECT_URI")
	if postLogoutRedirect == "" {
		postLogoutRedirect = redirectURL.Scheme + "://" + redirectURL.Host + "/logged-out"
	}
	postLogoutURL, err := url.Parse(postLogoutRedirect)
	if err != nil || !postLogoutURL.IsAbs() || postLogoutURL.Host == "" || postLogoutURL.User != nil || postLogoutURL.Opaque != "" ||
		postLogoutURL.RawPath != "" || postLogoutURL.Fragment != "" || postLogoutURL.RawQuery != "" || postLogoutURL.ForceQuery ||
		postLogoutURL.Path != "/logged-out" {
		return exampleConfig{}, errors.New("EXAMPLE_POST_LOGOUT_REDIRECT_URI must be an absolute URL without userinfo, query, or fragment")
	}
	if postLogoutURL.Scheme != "https" && (postLogoutURL.Scheme != "http" || !isLoopbackHost(postLogoutURL.Hostname())) {
		return exampleConfig{}, errors.New("EXAMPLE_POST_LOGOUT_REDIRECT_URI must use HTTPS except on loopback")
	}
	if !sameURLOrigin(postLogoutURL, redirectURL) {
		return exampleConfig{}, errors.New("EXAMPLE_POST_LOGOUT_REDIRECT_URI must use the authorization callback origin")
	}
	clientID := os.Getenv("EXAMPLE_CLIENT_ID")
	if clientID == "" || len(clientID) > 256 || strings.TrimSpace(clientID) != clientID {
		return exampleConfig{}, errors.New("EXAMPLE_CLIENT_ID is required and bounded")
	}
	scopes, err := canonicalExampleScopes(strings.Fields(defaultString(os.Getenv("EXAMPLE_SCOPES"), "openid profile email")))
	if err != nil {
		return exampleConfig{}, err
	}
	cookieSecure, err := strconv.ParseBool(defaultString(os.Getenv("EXAMPLE_COOKIE_SECURE"), "true"))
	if err != nil {
		return exampleConfig{}, errors.New("EXAMPLE_COOKIE_SECURE must be true or false")
	}
	cookieName := defaultString(os.Getenv("EXAMPLE_COOKIE_NAME"), "oneissuer_example")
	if len(cookieName) > 64 || !validCookieName(cookieName) {
		return exampleConfig{}, errors.New("EXAMPLE_COOKIE_NAME is invalid")
	}
	name := defaultString(os.Getenv("EXAMPLE_NAME"), "OneIssuer OIDC Example")
	if len(name) > 100 || strings.TrimSpace(name) == "" {
		return exampleConfig{}, errors.New("EXAMPLE_NAME is invalid")
	}
	addr := defaultString(os.Getenv("EXAMPLE_HTTP_ADDR"), ":8080")
	if strings.TrimSpace(addr) == "" || len(addr) > 256 {
		return exampleConfig{}, errors.New("EXAMPLE_HTTP_ADDR is invalid")
	}
	secret := os.Getenv("EXAMPLE_CLIENT_SECRET")
	if secretFile := os.Getenv("EXAMPLE_CLIENT_SECRET_FILE"); secretFile != "" {
		if secret != "" {
			return exampleConfig{}, errors.New("EXAMPLE_CLIENT_SECRET and EXAMPLE_CLIENT_SECRET_FILE are mutually exclusive")
		}
		// #nosec G304 G703 -- the operator-configured path is the intended secret-file
		// boundary; content is bounded and never included in errors or logs.
		encoded, readErr := os.ReadFile(secretFile)
		if readErr != nil || len(encoded) == 0 || len(encoded) > 2048 {
			return exampleConfig{}, errors.New("EXAMPLE_CLIENT_SECRET_FILE could not be read safely")
		}
		secret = string(encoded)
	}
	if len(secret) > 1024 || strings.ContainsAny(secret, "\r\n\x00") {
		return exampleConfig{}, errors.New("EXAMPLE_CLIENT_SECRET is invalid")
	}
	return exampleConfig{
		Name: name, Addr: addr, Issuer: issuer, ProviderBackchannel: backchannel,
		ClientID: clientID, ClientSecret: secret, RedirectURI: redirect, PostLogoutRedirectURI: postLogoutRedirect, Scopes: scopes,
		CookieName: cookieName, CookieSecure: cookieSecure,
	}, nil
}

func parseOrigin(raw string) (*url.URL, error) {
	value, err := url.Parse(raw)
	if err != nil || !value.IsAbs() || value.Host == "" || value.User != nil || value.Opaque != "" ||
		(value.Scheme != "http" && value.Scheme != "https") || value.Path != "" || value.RawPath != "" ||
		value.RawQuery != "" || value.ForceQuery || value.Fragment != "" {
		return nil, errors.New("value must be a canonical HTTP(S) origin")
	}
	if value.Scheme != "https" && !isLoopbackHost(value.Hostname()) && value.Hostname() != "oneissuer" {
		return nil, errors.New("HTTP is accepted only for explicit local development origins")
	}
	return value, nil
}

func canonicalExampleScopes(values []string) ([]string, error) {
	if len(values) < 1 || len(values) > 4 {
		return nil, errors.New("EXAMPLE_SCOPES must contain openid and only profile/email/offline_access additions")
	}
	result := append([]string(nil), values...)
	slices.Sort(result)
	for index, value := range result {
		if value != "openid" && value != "profile" && value != "email" && value != "offline_access" {
			return nil, errors.New("EXAMPLE_SCOPES contains an unsupported scope")
		}
		if index > 0 && result[index-1] == value {
			return nil, errors.New("EXAMPLE_SCOPES contains a duplicate")
		}
	}
	if !slices.Contains(result, "openid") {
		return nil, errors.New("EXAMPLE_SCOPES must include openid")
	}
	return result, nil
}

func validCookieName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", character) {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
