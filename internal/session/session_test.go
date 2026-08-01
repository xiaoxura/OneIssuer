package session

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOpaqueTokensCSRFAndPrivacyMetadata(t *testing.T) {
	t.Parallel()
	manager, err := NewTokenManager(bytes.NewReader(bytes.Repeat([]byte{9}, 512)), 24*time.Hour, 2*time.Hour, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	issued, err := manager.NewAuthenticated(uuid.New(), now, "sensitive user agent", netip.MustParseAddr("203.0.113.129"))
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token == string(issued.Record.TokenHash) || len(issued.Record.TokenHash) != 32 || issued.Record.IPPrefix != "203.0.113.0/24" {
		t.Fatalf("unsafe issued record: %+v", issued.Record)
	}
	if !csrfMatches(issued.CSRFToken, issued.Record.CSRFHash) || csrfMatches("c1_"+strings.Repeat("A", 43), issued.Record.CSRFHash) {
		t.Fatal("CSRF digest comparison failed")
	}
	preauth, err := manager.NewPreAuth(uuid.New(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ValidatePreAuth(preauth.Record, preauth.Token, preauth.CSRFToken, now); err != nil {
		t.Fatal(err)
	}
	if err := manager.ValidatePreAuth(preauth.Record, preauth.Token, "c1_"+strings.Repeat("B", 43), now); !errors.Is(err, ErrInvalidCSRF) {
		t.Fatalf("cross-flow CSRF error=%v", err)
	}
}

func TestCookieAttributesAndClearing(t *testing.T) {
	t.Parallel()
	manager := NewCookieManager("__Host-oneissuer_session", true, 24*time.Hour, 15*time.Minute)
	now := time.Now().UTC()
	issued := Issued{Token: "s1_value", CSRFToken: "c1_value", Record: Record{CreatedAt: now, CSRFExpiresAt: now.Add(15 * time.Minute)}}
	recorder := httptest.NewRecorder()
	manager.SetAuthenticated(recorder, issued)
	cookies := recorder.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("cookie count=%d", len(cookies))
	}
	for _, cookie := range cookies {
		if cookie.Path != "/" || !cookie.Secure || cookie.Domain != "" {
			t.Fatalf("unsafe cookie attributes: %+v", cookie)
		}
		if cookie.Name == manager.SessionName && (!cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode) {
			t.Fatalf("unsafe session cookie: %+v", cookie)
		}
	}
	clearRecorder := httptest.NewRecorder()
	manager.ClearAuthenticated(clearRecorder)
	for _, cookie := range clearRecorder.Result().Cookies() {
		if cookie.MaxAge >= 0 {
			t.Fatalf("clear cookie MaxAge=%d", cookie.MaxAge)
		}
	}
}
