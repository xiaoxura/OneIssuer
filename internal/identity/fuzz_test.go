package identity

import (
	"testing"
	"unicode/utf8"
)

func FuzzIdentityNormalization(f *testing.F) {
	for _, seed := range []string{
		"Alice", "Ａlice", "Straße", "alice@example.invalid", "ALICE@EXAMPLE.INVALID", "", "a@b", " 用户名 ",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}

		display, normalized, err := NormalizeUsername(raw)
		if err == nil {
			if !utf8.ValidString(display) || !utf8.ValidString(normalized) || display == "" || normalized == "" {
				t.Fatalf("successful username normalization returned invalid output")
			}
			displayAgain, normalizedAgain, secondErr := NormalizeUsername(display)
			if secondErr != nil || displayAgain != display || normalizedAgain != normalized {
				t.Fatalf("username normalization is not idempotent")
			}
		}

		email, emailNormalized, emailErr := NormalizeEmail(raw)
		if emailErr == nil {
			if !utf8.ValidString(email) || !utf8.ValidString(emailNormalized) || email == "" || emailNormalized == "" {
				t.Fatalf("successful email normalization returned invalid output")
			}
			emailAgain, normalizedAgain, secondErr := NormalizeEmail(email)
			if secondErr != nil || emailAgain != email || normalizedAgain != emailNormalized {
				t.Fatalf("email normalization is not idempotent")
			}
		}

		identifier, identifierErr := NormalizeLoginIdentifier(raw)
		if identifierErr == nil {
			expected := normalized
			if emailErr == nil {
				expected = emailNormalized
			}
			if identifier != expected {
				t.Fatalf("login identifier selected an inconsistent namespace")
			}
		}
	})
}
