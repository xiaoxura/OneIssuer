package oidc

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
)

func TestFositeAdapterExposesOnlyFrozenPublicProtocolProfile(t *testing.T) {
	t.Parallel()
	value := clientdomain.Client{
		ID: uuid.New(), ClientID: "ois_cli_public", Type: clientdomain.TypeConfidential,
		TokenEndpointAuthMethod: clientdomain.AuthMethodClientSecretBasic,
		RedirectURIs:            []string{"https://rp.example/cb"}, Scopes: []string{"offline_access", "profile", "openid", "email"},
	}
	adapted := newFositeClient(value)
	if adapted.GetID() != value.ClientID || adapted.IsPublic() || len(adapted.GetHashedSecret()) != 0 {
		t.Fatalf("unsafe Fosite adapter: id=%q public=%v secret_len=%d", adapted.GetID(), adapted.IsPublic(), len(adapted.GetHashedSecret()))
	}
	if !reflect.DeepEqual([]string(adapted.GetGrantTypes()), []string{"authorization_code"}) ||
		!reflect.DeepEqual([]string(adapted.GetResponseTypes()), []string{"code"}) ||
		!reflect.DeepEqual([]string(adapted.GetScopes()), []string{"email", "openid", "profile"}) {
		t.Fatalf("unexpected Fosite profile grants=%v responses=%v scopes=%v", adapted.GetGrantTypes(), adapted.GetResponseTypes(), adapted.GetScopes())
	}
	redirects := adapted.GetRedirectURIs()
	redirects[0] = "https://evil.example"
	if adapted.GetRedirectURIs()[0] != value.RedirectURIs[0] {
		t.Fatal("Fosite adapter leaked mutable Client storage")
	}
}
