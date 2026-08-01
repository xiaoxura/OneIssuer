package authflow

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func FuzzAuthorizationTransactionToken(f *testing.F) {
	f.Add("")
	f.Add("t1_invalid")
	f.Add("t1_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	f.Add("s1_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)))

	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > 4096 {
			t.Skip()
		}
		digest := HashToken(token)
		if len(digest) != 32 || !bytes.Equal(digest, HashToken(token)) {
			t.Fatal("transaction digest is not deterministic and 256-bit")
		}
		if !validToken(token) {
			return
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, "t1_"))
		if err != nil || len(decoded) != 32 || !strings.HasPrefix(token, "t1_") {
			t.Fatal("validToken accepted a non-canonical token")
		}
	})
}
