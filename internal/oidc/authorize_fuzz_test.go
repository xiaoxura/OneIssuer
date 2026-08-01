package oidc

import (
	"context"
	"testing"
)

func FuzzParseAuthorizationRequest(f *testing.F) {
	resolver, values := validAuthorizeFixture()
	f.Add(values.Encode())
	f.Add("%ZZ")
	f.Add("client_id=x&client_id=y")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16<<10 {
			t.Skip()
		}
		request, err := ParseAuthorizationRequest(context.Background(), raw, resolver)
		if err == nil && (request.Client.ClientID == "" || request.RedirectURI == "" || request.PKCEChallenge == "") {
			t.Fatal("successful parse returned incomplete verified request")
		}
	})
}
