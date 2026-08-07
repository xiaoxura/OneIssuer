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
	// RevocationPath is the RFC 7009 owning-Client endpoint.
	RevocationPath = "/oauth2/revoke"
	// IntrospectionPath is the restricted RFC 7662 Confidential-owning-Client endpoint.
	IntrospectionPath = "/oauth2/introspect"
	// LogoutPath accepts standard RP-Initiated Logout GET/query and POST/form requests.
	LogoutPath = "/oauth2/logout"
	// LogoutConfirmPath is the clean cookie-only hosted confirmation continuation.
	LogoutConfirmPath = "/oauth2/logout/confirm"
	// UserInfoPath is the only supported Access Token audience and resource route.
	UserInfoPath = "/oauth2/userinfo"
	// JWKSPath publishes the immutable public-only process key ring.
	JWKSPath = "/oauth2/jwks"
)

// ProviderMetadata is the exact minimal capability statement for phase three.
// Field order is intentional so encoded snapshots are stable and reviewable.
type ProviderMetadata struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	RevocationEndpoint                        string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint,omitempty"`
	UserInfoEndpoint                          string   `json:"userinfo_endpoint"`
	JWKSURI                                   string   `json:"jwks_uri"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	ResponseModesSupported                    []string `json:"response_modes_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	IDTokenSigningAlgorithmsSupported         []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	ScopesSupported                           []string `json:"scopes_supported"`
	ClaimsSupported                           []string `json:"claims_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	PromptValuesSupported                     []string `json:"prompt_values_supported"`
}

// MetadataOption enables a capability only when its complete live route set is
// mounted. The default deliberately omits RP logout during partial startup.
type MetadataOption func(*ProviderMetadata)

// WithEndSessionEndpoint advertises the live RP-Initiated Logout route.
func WithEndSessionEndpoint() MetadataOption {
	return func(metadata *ProviderMetadata) {
		value := *metadata
		// Issuer is canonicalized and validated by BuildProviderMetadata before
		// options are applied, so direct concatenation preserves its origin bytes.
		value.EndSessionEndpoint = metadata.Issuer + LogoutPath
		*metadata = value
	}
}

// BuildProviderMetadata derives every public URL from one already-validated,
// origin-only Issuer. It rejects path/query/fragment input rather than silently
// normalizing a caller mistake. Optional capabilities are applied after the
// frozen baseline has been built.
func BuildProviderMetadata(issuer *url.URL, options ...MetadataOption) (ProviderMetadata, error) {
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
	metadata := ProviderMetadata{
		Issuer:                                    issuer.String(),
		AuthorizationEndpoint:                     endpoint(AuthorizePath),
		TokenEndpoint:                             endpoint(TokenPath),
		RevocationEndpoint:                        endpoint(RevocationPath),
		IntrospectionEndpoint:                     endpoint(IntrospectionPath),
		UserInfoEndpoint:                          endpoint(UserInfoPath),
		JWKSURI:                                   endpoint(JWKSPath),
		ResponseTypesSupported:                    []string{"code"},
		ResponseModesSupported:                    []string{"query"},
		GrantTypesSupported:                       []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:                     []string{"public"},
		IDTokenSigningAlgorithmsSupported:         []string{"RS256"},
		TokenEndpointAuthMethodsSupported:         []string{"none", "client_secret_basic"},
		RevocationEndpointAuthMethodsSupported:    []string{"none", "client_secret_basic"},
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		ScopesSupported:                           []string{"openid", "profile", "email", "offline_access"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "azp",
			"name", "preferred_username", "email", "email_verified",
		},
		CodeChallengeMethodsSupported: []string{"S256"},
		PromptValuesSupported:         []string{"none", "login", "consent", "create"},
	}
	for _, option := range options {
		if option != nil {
			option(&metadata)
		}
	}
	return metadata, nil
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
