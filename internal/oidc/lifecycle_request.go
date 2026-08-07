package oidc

import (
	"context"
	"net/http"
	"net/url"

	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/ory/fosite"
)

// VerifiedRevocationRequest retains a clear Token only in the protocol→service
// call frame. It must never be logged or persisted.
type VerifiedRevocationRequest struct {
	Client clientdomain.Client
	Token  string
	Hint   string
}

// VerifiedIntrospectionRequest is restricted to an authenticated Confidential
// owning Client. Token remains transient.
type VerifiedIntrospectionRequest struct {
	Client clientdomain.Client
	Token  string
	Hint   string
}

// ParseRevocationRequest implements the strict RFC 7009 form/auth boundary.
func ParseRevocationRequest(ctx context.Context, form url.Values, header http.Header, clients TokenClientResolver) (VerifiedRevocationRequest, error) {
	if clients == nil || !validTokenFormUTF8(form) || !validLifecycleForm(form) {
		return VerifiedRevocationRequest{}, tokenError(fosite.ErrInvalidRequest, false)
	}
	if len(form["client_secret"]) != 0 {
		return VerifiedRevocationRequest{}, tokenError(fosite.ErrInvalidClient, len(header.Values("Authorization")) != 0)
	}
	clientValue, challenged, err := authenticateTokenClient(ctx, form, header, clients)
	if err != nil {
		return VerifiedRevocationRequest{}, tokenError(fosite.ErrInvalidClient, challenged)
	}
	return VerifiedRevocationRequest{Client: clientValue, Token: form.Get("token"), Hint: form.Get("token_type_hint")}, nil
}

// ParseIntrospectionRequest implements the strict RFC 7662 form boundary and
// rejects public callers before any Token lookup.
func ParseIntrospectionRequest(ctx context.Context, form url.Values, header http.Header, clients TokenClientResolver) (VerifiedIntrospectionRequest, error) {
	if clients == nil || !validTokenFormUTF8(form) || !validLifecycleForm(form) {
		return VerifiedIntrospectionRequest{}, tokenError(fosite.ErrInvalidRequest, false)
	}
	if len(form["client_secret"]) != 0 {
		return VerifiedIntrospectionRequest{}, tokenError(fosite.ErrInvalidClient, true)
	}
	clientValue, challenged, err := authenticateTokenClient(ctx, form, header, clients)
	if err != nil || clientValue.Type != clientdomain.TypeConfidential || clientValue.TokenEndpointAuthMethod != clientdomain.AuthMethodClientSecretBasic {
		return VerifiedIntrospectionRequest{}, tokenError(fosite.ErrInvalidClient, challenged || clientValue.Type != clientdomain.TypeConfidential)
	}
	return VerifiedIntrospectionRequest{Client: clientValue, Token: form.Get("token"), Hint: form.Get("token_type_hint")}, nil
}

func validLifecycleForm(form url.Values) bool {
	if len(form["token"]) != 1 || form.Get("token") == "" || len(form["token_type_hint"]) > 1 ||
		len(form["client_id"]) > 1 || len(form["client_secret"]) > 1 {
		return false
	}
	for name := range form {
		if name != "token" && name != "token_type_hint" && name != "client_id" && name != "client_secret" {
			return false
		}
	}
	return true
}
