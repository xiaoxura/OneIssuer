package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzPrivateJWKLoading(f *testing.F) {
	seedPath := filepath.Join(f.TempDir(), "seed.jwk")
	if _, err := Generate(seedPath, 2048, nil); err != nil {
		f.Fatal(err)
	}
	valid, err := os.ReadFile(seedPath)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"kty":"oct","k":"c2VjcmV0","alg":"HS256","use":"sig","kid":"canary"}`))
	f.Add([]byte(`{"kty":"RSA","alg":"none"}`))
	f.Add([]byte(`{"d":"private-canary"}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) == 0 || len(body) > maxKeyFileSize+1 {
			return
		}
		path := filepath.Join(t.TempDir(), "candidate.jwk")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		key, loadErr := loadPrivate(path)
		if loadErr == nil {
			if key.IsPublic() || key.KeyID == "" || key.Algorithm != Algorithm || key.Use != "sig" {
				t.Fatalf("loader accepted a key outside the private RS256 profile: %+v", key)
			}
		}
	})
}
