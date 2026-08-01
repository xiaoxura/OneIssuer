// Package oidc defines OneIssuer's phase-three wire profile without allowing
// protocol-library types to leak into the identity, client, or session domains.
package oidc

import (
	"encoding/json"
	"errors"
	"net/url"
)

const (
	// DiscoveryPath is deliberately routed only after every advertised endpoint
	// is implemented. Metadata construction can be tested before that gate opens.
	DiscoveryPath = "/.well-known/openid-configuration"
	// AuthorizePath is the advertised Authorization Endpoint.
	AuthorizePath = "/oauth2/authorize"
	// AuthorizeContinuePath is an internal browser continuation carrying only a
	// server-issued opaque transaction value; it is never advertised in Metadata.
	AuthorizeContinuePath = "/oauth2/authorize/continue"
	// TokenPath is the advertised form-encoded Authorization Code Token Endpoint.
	// #nosec G101 -- this is a public protocol route, not a credential literal.
	TokenPath = "/oauth2/token"
	// UserInfoPath is the only supported Access Token audience and resource route.
	UserInfoPath = "/oauth2/userinfo"
	// JWKSPath publishes the immutable public-only process key ring.
	JWKSPath = "/oauth2/jwks"
)

// ProviderMetadata is the exact minimal capability statement for phase three.
// Field order is intentional so encoded snapshots are stable and reviewable.
type ProviderMetadata struct {
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

// BuildProviderMetadata derives every public URL from one already-validated,
// origin-only Issuer. It rejects path/query/fragment input rather than silently
// normalizing a caller mistake.
func BuildProviderMetadata(issuer *url.URL) (ProviderMetadata, error) {
	if issuer == nil || !issuer.IsAbs() || issuer.Host == "" || issuer.User != nil || issuer.Opaque != "" ||
		(issuer.Scheme != "http" && issuer.Scheme != "https") || issuer.Path != "" || issuer.RawPath != "" ||
		issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" {
		return ProviderMetadata{}, errors.New("OIDC issuer must be a canonical origin")
	}

	endpoint := func(path string) string {
		value := *issuer
		value.Path = path
		return value.String()
	}
	return ProviderMetadata{
		Issuer:                            issuer.String(),
		AuthorizationEndpoint:             endpoint(AuthorizePath),
		TokenEndpoint:                     endpoint(TokenPath),
		UserInfoEndpoint:                  endpoint(UserInfoPath),
		JWKSURI:                           endpoint(JWKSPath),
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgorithmsSupported: []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "azp",
			"name", "preferred_username", "email", "email_verified",
		},
		CodeChallengeMethodsSupported: []string{"S256"},
		PromptValuesSupported:         []string{"none", "login", "consent", "create"},
	}, nil
}

// MarshalProviderMetadata emits deterministic compact JSON followed by a single
// newline. Callers may cache these immutable bytes for the process lifetime.
func MarshalProviderMetadata(metadata ProviderMetadata) ([]byte, error) {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, errors.New("OIDC provider metadata serialization failed")
	}
	return append(encoded, '\n'), nil
}
