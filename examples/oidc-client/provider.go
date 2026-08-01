package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const maxProviderResponseBytes = 64 << 10

type providerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgorithmsSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	PromptValuesSupported             []string `json:"prompt_values_supported"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

type idTokenClaims struct {
	Issuer            string  `json:"iss"`
	Subject           string  `json:"sub"`
	Audience          string  `json:"aud"`
	AuthorizedParty   string  `json:"azp"`
	ExpiresAt         int64   `json:"exp"`
	IssuedAt          int64   `json:"iat"`
	AuthTime          int64   `json:"auth_time"`
	Nonce             string  `json:"nonce,omitempty"`
	Name              *string `json:"name,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Email             *string `json:"email,omitempty"`
	EmailVerified     *bool   `json:"email_verified,omitempty"`
}

type userInfoResponse struct {
	Subject           string  `json:"sub"`
	Name              *string `json:"name,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Email             *string `json:"email,omitempty"`
	EmailVerified     *bool   `json:"email_verified,omitempty"`
}

func discoverProvider(ctx context.Context, client *http.Client, cfg exampleConfig) (providerMetadata, error) {
	target := advertisedEndpoint(cfg.Issuer, "/.well-known/openid-configuration")
	var metadata providerMetadata
	if err := providerJSON(ctx, client, cfg, http.MethodGet, target, nil, nil, &metadata); err != nil {
		return providerMetadata{}, errors.New("provider discovery failed")
	}
	if err := validateProviderMetadata(cfg, metadata); err != nil {
		return providerMetadata{}, err
	}
	return metadata, nil
}

func validateProviderMetadata(cfg exampleConfig, metadata providerMetadata) error {
	issuer := cfg.Issuer.String()
	if metadata.Issuer != issuer || metadata.AuthorizationEndpoint != issuer+"/oauth2/authorize" ||
		metadata.TokenEndpoint != issuer+"/oauth2/token" || metadata.UserInfoEndpoint != issuer+"/oauth2/userinfo" || metadata.JWKSURI != issuer+"/oauth2/jwks" ||
		!slices.Equal(metadata.ResponseTypesSupported, []string{"code"}) || !slices.Equal(metadata.ResponseModesSupported, []string{"query"}) ||
		!slices.Equal(metadata.GrantTypesSupported, []string{"authorization_code"}) || !slices.Equal(metadata.SubjectTypesSupported, []string{"public"}) ||
		!slices.Equal(metadata.IDTokenSigningAlgorithmsSupported, []string{"RS256"}) ||
		!slices.Contains(metadata.TokenEndpointAuthMethodsSupported, expectedAuthMethod(cfg)) ||
		!slices.Equal(metadata.ClaimsSupported, []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "azp",
			"name", "preferred_username", "email", "email_verified",
		}) ||
		!slices.Equal(metadata.CodeChallengeMethodsSupported, []string{"S256"}) {
		return errors.New("provider metadata does not match the example security profile")
	}
	for _, scope := range cfg.Scopes {
		if !slices.Contains(metadata.ScopesSupported, scope) {
			return errors.New("provider metadata does not support a configured scope")
		}
	}
	return nil
}

func exchangeAuthorizationCode(ctx context.Context, client *http.Client, cfg exampleConfig, metadata providerMetadata, code, verifier string) (tokenResponse, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {cfg.RedirectURI}, "code_verifier": {verifier},
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.ClientSecret == "" {
		form.Set("client_id", cfg.ClientID)
	} else {
		credentials := url.QueryEscape(cfg.ClientID) + ":" + url.QueryEscape(cfg.ClientSecret)
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	var response tokenResponse
	if err := providerJSON(ctx, client, cfg, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()), headers, &response); err != nil {
		return tokenResponse{}, errors.New("authorization code exchange failed")
	}
	if response.AccessToken == "" || response.IDToken == "" || response.TokenType != "Bearer" || response.ExpiresIn <= 0 || response.ExpiresIn > 1800 {
		return tokenResponse{}, errors.New("token response does not match the example security profile")
	}
	scopes, err := canonicalExampleScopes(strings.Split(response.Scope, " "))
	if err != nil || strings.Join(scopes, " ") != response.Scope {
		return tokenResponse{}, errors.New("token response scope is invalid")
	}
	for _, scope := range scopes {
		if !slices.Contains(cfg.Scopes, scope) {
			return tokenResponse{}, errors.New("token response expanded the requested scope")
		}
	}
	return response, nil
}

func verifyIDToken(ctx context.Context, client *http.Client, cfg exampleConfig, metadata providerMetadata, compact, nonce string, now time.Time) (idTokenClaims, error) {
	if compact == "" || len(compact) > 16<<10 || strings.Count(compact, ".") != 2 || strings.TrimSpace(compact) != compact {
		return idTokenClaims{}, errors.New("ID Token is malformed")
	}
	object, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(object.Signatures) != 1 {
		return idTokenClaims{}, errors.New("ID Token signature envelope is invalid")
	}
	header := object.Signatures[0].Header
	typ, typeOK := header.ExtraHeaders[jose.HeaderType].(string)
	if header.Algorithm != string(jose.RS256) || header.KeyID == "" || !typeOK || typ != "JWT" || len(header.ExtraHeaders) != 1 || header.JSONWebKey != nil || header.Nonce != "" {
		return idTokenClaims{}, errors.New("ID Token header is invalid")
	}
	keys, err := fetchPublicKeys(ctx, client, cfg, metadata.JWKSURI)
	if err != nil {
		return idTokenClaims{}, err
	}
	var key *rsa.PublicKey
	for _, candidate := range keys {
		public, ok := candidate.Key.(*rsa.PublicKey)
		if candidate.KeyID == header.KeyID && candidate.Algorithm == string(jose.RS256) && candidate.Use == "sig" && candidate.IsPublic() && ok && public != nil && public.N != nil && public.N.BitLen() >= 2048 {
			if key != nil {
				return idTokenClaims{}, errors.New("JWKS contains an ambiguous signing key")
			}
			key = public
		}
	}
	if key == nil {
		return idTokenClaims{}, errors.New("ID Token signing key is not trusted")
	}
	payload, err := object.Verify(key)
	if err != nil {
		return idTokenClaims{}, errors.New("ID Token signature is invalid")
	}
	var claims idTokenClaims
	if err := decodeStrictJSON(bytes.NewReader(payload), &claims); err != nil {
		return idTokenClaims{}, errors.New("ID Token claims are invalid")
	}
	now = now.UTC()
	const skew = 30 * time.Second
	if claims.Issuer != metadata.Issuer || claims.Subject == "" || claims.Audience != cfg.ClientID || claims.AuthorizedParty != cfg.ClientID ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || claims.AuthTime <= 0 ||
		time.Unix(claims.IssuedAt, 0).After(now.Add(skew)) || time.Unix(claims.AuthTime, 0).After(now.Add(skew)) || !now.Before(time.Unix(claims.ExpiresAt, 0).Add(skew)) ||
		time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > 15*time.Minute ||
		subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return idTokenClaims{}, errors.New("ID Token claims do not match the authorization request")
	}
	if (!slices.Contains(cfg.Scopes, "profile") && (claims.Name != nil || claims.PreferredUsername != nil)) ||
		(!slices.Contains(cfg.Scopes, "email") && (claims.Email != nil || claims.EmailVerified != nil)) {
		return idTokenClaims{}, errors.New("ID Token contains claims outside the granted scope")
	}
	return claims, nil
}

func fetchUserInfo(ctx context.Context, client *http.Client, cfg exampleConfig, metadata providerMetadata, accessToken, subject string) (userInfoResponse, error) {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+accessToken)
	var response userInfoResponse
	if err := providerJSON(ctx, client, cfg, http.MethodGet, metadata.UserInfoEndpoint, nil, headers, &response); err != nil {
		return userInfoResponse{}, errors.New("UserInfo request failed")
	}
	if response.Subject == "" || subtle.ConstantTimeCompare([]byte(response.Subject), []byte(subject)) != 1 {
		return userInfoResponse{}, errors.New("UserInfo subject does not match ID Token")
	}
	if (!slices.Contains(cfg.Scopes, "profile") && (response.Name != nil || response.PreferredUsername != nil)) ||
		(!slices.Contains(cfg.Scopes, "email") && (response.Email != nil || response.EmailVerified != nil)) {
		return userInfoResponse{}, errors.New("UserInfo contains claims outside the granted scope")
	}
	return response, nil
}

func fetchPublicKeys(ctx context.Context, client *http.Client, cfg exampleConfig, target string) ([]jose.JSONWebKey, error) {
	var set jose.JSONWebKeySet
	if err := providerJSON(ctx, client, cfg, http.MethodGet, target, nil, nil, &set); err != nil || len(set.Keys) == 0 || len(set.Keys) > 10 {
		return nil, errors.New("provider JWKS is unavailable")
	}
	seen := make(map[string]bool, len(set.Keys))
	for _, candidate := range set.Keys {
		public, ok := candidate.Key.(*rsa.PublicKey)
		if !candidate.IsPublic() || !ok || public == nil || public.N == nil || public.N.BitLen() < 2048 ||
			candidate.KeyID == "" || candidate.Algorithm != string(jose.RS256) || candidate.Use != "sig" || seen[candidate.KeyID] {
			return nil, errors.New("provider JWKS violates the public RS256 profile")
		}
		seen[candidate.KeyID] = true
	}
	return set.Keys, nil
}

func providerJSON(ctx context.Context, client *http.Client, cfg exampleConfig, method, advertised string, body io.Reader, headers http.Header, destination any) error {
	target, err := cfg.backchannelURL(advertised)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return errors.New("provider request could not be created")
	}
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("provider request failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxProviderResponseBytes))
		return fmt.Errorf("provider returned HTTP status class %dxx", response.StatusCode/100)
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return errors.New("provider response content type is invalid")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errors.New("provider response content type is invalid")
	}
	limited := io.LimitReader(response.Body, maxProviderResponseBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) == 0 || len(encoded) > maxProviderResponseBytes {
		return errors.New("provider response size is invalid")
	}
	if err := decodeStrictJSON(bytes.NewReader(encoded), destination); err != nil {
		return errors.New("provider response JSON is invalid")
	}
	return nil
}

func decodeStrictJSON(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func (cfg exampleConfig) backchannelURL(advertised string) (string, error) {
	value, err := url.Parse(advertised)
	if err != nil || !value.IsAbs() || value.User != nil || value.Fragment != "" || value.Scheme != cfg.Issuer.Scheme || !strings.EqualFold(value.Host, cfg.Issuer.Host) {
		return "", errors.New("provider advertised an endpoint outside its Issuer origin")
	}
	if cfg.ProviderBackchannel != nil {
		value.Scheme = cfg.ProviderBackchannel.Scheme
		value.Host = cfg.ProviderBackchannel.Host
	}
	return value.String(), nil
}

func advertisedEndpoint(issuer *url.URL, path string) string {
	value := *issuer
	value.Path = path
	return value.String()
}

func expectedAuthMethod(cfg exampleConfig) string {
	if cfg.ClientSecret == "" {
		return "none"
	}
	return "client_secret_basic"
}
