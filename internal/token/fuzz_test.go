package token

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func FuzzAccessTokenVerification(f *testing.F) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	digest := sha256.Sum256(private.N.Bytes())
	kid := base64.RawURLEncoding.EncodeToString(digest[:])
	keys := &testKeyStore{
		private: private, kid: kid,
		public: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}},
	}
	service, err := NewService(&fakeRepository{}, keys, bytes.NewReader(make([]byte, 64)), testIssuer, 5*time.Minute, 10*time.Minute, 30*time.Second, nil)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	claims := AccessTokenClaims{
		Issuer: testIssuer, Subject: "usr_subject", Audience: testIssuer + "/oauth2/userinfo",
		ClientID: "ois_cli_fixture", Scope: "openid", IssuedAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(),
		JWTID: "jti_" + base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := signPayload(keys.private, jose.RS256, kid, "at+jwt", payload, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.e30.")
	f.Add("header.payload.signature")
	f.Add(strings.Repeat("a", maxCompactTokenBytes+1))

	f.Fuzz(func(t *testing.T, compact string) {
		if len(compact) > 128<<10 {
			t.Skip()
		}
		verified, verifyErr := service.verifyAccessToken(compact, now)
		if verifyErr == nil {
			if verified.Issuer != testIssuer || verified.Audience != testIssuer+"/oauth2/userinfo" || verified.Subject == "" ||
				verified.ClientID == "" || verified.Scope != "openid" || !validJTI(verified.JWTID) {
				t.Fatalf("accepted JWT violates fixed profile: %+v", verified)
			}
		}
	})
}
