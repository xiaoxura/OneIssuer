package client

import (
	"reflect"
	"strings"
	"testing"
)

func FuzzClientURIAndScopes(f *testing.F) {
	f.Add("https://client.example.invalid/callback", "openid profile")
	f.Add("http://127.0.0.1:8080/callback", "email openid email")
	f.Add("https://client.example.invalid/callback#fragment", "offline_access")
	f.Add("javascript:alert(1)", "openid unknown")
	f.Add("", "")

	service := NewService(nil, nil, true, nil)
	f.Fuzz(func(t *testing.T, rawURI, rawScopes string) {
		if len(rawURI) > 4096 || len(rawScopes) > 4096 {
			t.Skip()
		}
		if err := validateURI(rawURI, true); err == nil {
			if strings.TrimSpace(rawURI) != rawURI || strings.Contains(rawURI, "*") || validateURI(rawURI, true) != nil {
				t.Fatalf("accepted URI is not stable under validation")
			}
		}

		scopes := strings.Fields(rawScopes)
		validated, err := service.validateScopes(scopes)
		if err != nil {
			return
		}
		if !contains(validated, "openid") {
			t.Fatal("accepted scope set omitted openid")
		}
		validatedAgain, secondErr := service.validateScopes(validated)
		if secondErr != nil || !reflect.DeepEqual(validatedAgain, validated) {
			t.Fatal("scope canonicalization is not idempotent")
		}
	})
}
