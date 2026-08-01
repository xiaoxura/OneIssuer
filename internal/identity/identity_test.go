package identity

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/oneissuer/oneissuer/internal/config"
)

func TestNormalizationRulesAreStable(t *testing.T) {
	t.Parallel()
	display, normalized, err := NormalizeUsername("  A\u030Alice-1  ")
	if err != nil || display != "Ålice-1" || normalized != "ålice-1" {
		t.Fatalf("NormalizeUsername() = %q %q %v", display, normalized, err)
	}
	emailDisplay, emailNormalized, err := NormalizeEmail(" Alice+Tag@Example.INVALID ")
	if err != nil || emailDisplay != "Alice+Tag@Example.INVALID" || emailNormalized != "alice+tag@example.invalid" {
		t.Fatalf("NormalizeEmail() = %q %q %v", emailDisplay, emailNormalized, err)
	}
	if strings.Contains(emailNormalized, "alice@example") {
		t.Fatal("email provider-specific +tag rewriting occurred")
	}
	for _, invalid := range []string{"ab", "bad name", "-leading", "trailing-"} {
		if _, _, err := NormalizeUsername(invalid); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("NormalizeUsername(%q) error=%v", invalid, err)
		}
	}
}

func TestPasswordHashVerifyAndRehash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	old, err := NewPasswordHasher(Argon2Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 1, bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := old.Hash(ctx, " exact password with spaces ")
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewPasswordHasher(Argon2Params{MemoryKiB: 8 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}, 1, bytes.NewReader(bytes.Repeat([]byte{2}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	matches, rehash, err := current.Verify(ctx, " exact password with spaces ", encoded)
	if err != nil || !matches || !rehash {
		t.Fatalf("Verify() matches=%v rehash=%v err=%v", matches, rehash, err)
	}
	matches, _, err = current.Verify(ctx, "exact password with spaces", encoded)
	if err != nil || matches {
		t.Fatalf("trimmed password unexpectedly matched: matches=%v err=%v", matches, err)
	}
	if _, _, err := current.Verify(ctx, "anything", "$argon2id$unsafe"); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("malformed PHC error=%v", err)
	}
}

func TestPasswordPolicyBoundsAndDummyLogin(t *testing.T) {
	t.Parallel()
	policy := PasswordPolicy{MinLength: 15, MaxBytes: 64}
	if err := policy.ValidatePassword("123456789012345"); err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidatePassword(" 1234567890123 "); err != nil {
		t.Fatal("policy must not trim passwords")
	}
	secret := strings.Repeat("secret", 20)
	if err := policy.ValidatePassword(secret); !errors.Is(err, ErrInvalidInput) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe policy error=%v", err)
	}
	service, err := NewService(context.Background(), config.PasswordConfig{
		MinLength: 15, MaxBytes: 64, Argon2MemoryKiB: 8 * 1024, Argon2Time: 1, Argon2Threads: 1, MaxConcurrent: 1,
	}, bytes.NewReader(bytes.Repeat([]byte{7}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.VerifyLogin(context.Background(), "not-a-real-password", nil); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("dummy login error=%v", err)
	}
}
