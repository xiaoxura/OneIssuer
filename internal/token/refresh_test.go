package token

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRefreshTokenGrammarAndDomainSeparatedDigest(t *testing.T) {
	t.Parallel()
	tokenValue, digest, err := GenerateRefreshToken(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if len(tokenValue) != 46 || len(digest) != sha256.Size || bytes.Contains(digest, []byte(tokenValue)) {
		t.Fatalf("clear length=%d digest length=%d", len(tokenValue), len(digest))
	}
	presented, err := DigestPresentedRefreshToken(tokenValue)
	if err != nil || !bytes.Equal(presented, digest) {
		t.Fatalf("presented digest=%x error=%v", presented, err)
	}
	for _, invalid := range []string{"", "r2_" + tokenValue[3:], tokenValue + "=", tokenValue[:len(tokenValue)-1], "r1_*******************************************"} {
		if _, err := DigestPresentedRefreshToken(invalid); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("DigestPresentedRefreshToken(%q) error=%v", invalid, err)
		}
	}
	accessDigest := sha256.Sum256([]byte("oneissuer:access-token-jti:v1:" + tokenValue))
	if bytes.Equal(digest, accessDigest[:]) {
		t.Fatal("Refresh and Access digest domains collided")
	}
}

func TestRefreshDeadlinesAndAbsoluteCap(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	rolling, absolute, err := RefreshDeadlines(now, 30*24*time.Hour, 90*24*time.Hour)
	if err != nil || !rolling.Equal(now.Add(30*24*time.Hour)) || !absolute.Equal(now.Add(90*24*time.Hour)) {
		t.Fatalf("rolling=%v absolute=%v error=%v", rolling, absolute, err)
	}
	replacement, err := ReplacementRefreshExpiry(absolute.Add(-time.Hour), 30*24*time.Hour, absolute)
	if err != nil || !replacement.Equal(absolute) {
		t.Fatalf("replacement=%v error=%v", replacement, err)
	}
	for _, test := range []struct {
		rolling  time.Duration
		absolute time.Duration
	}{{time.Minute, 24 * time.Hour}, {31 * 24 * time.Hour, 90 * 24 * time.Hour}, {30 * 24 * time.Hour, 23 * time.Hour}, {30 * 24 * time.Hour, 366 * 24 * time.Hour}} {
		if _, _, err := RefreshDeadlines(now, test.rolling, test.absolute); !errors.Is(err, ErrInvalid) {
			t.Errorf("RefreshDeadlines(%v,%v) error=%v", test.rolling, test.absolute, err)
		}
	}
}

func TestCanonicalRefreshScopes(t *testing.T) {
	t.Parallel()
	got, err := CanonicalRefreshScopes([]string{"profile", "openid", "offline_access"})
	if err != nil || !reflect.DeepEqual(got, []string{"offline_access", "openid", "profile"}) {
		t.Fatalf("scopes=%q error=%v", got, err)
	}
	for _, invalid := range [][]string{{"openid"}, {"offline_access"}, {"offline_access", "openid", "openid"}} {
		if _, err := CanonicalRefreshScopes(invalid); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("CanonicalRefreshScopes(%q) error=%v", invalid, err)
		}
	}
}
