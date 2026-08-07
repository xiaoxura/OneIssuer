package httpserver

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oneissuer/oneissuer/internal/consent"
)

func TestDecodeGrantRevokeJSONExactSchema(t *testing.T) {
	t.Parallel()
	publicID := httpGrantClientID(1)
	tests := []struct {
		name        string
		contentType string
		body        string
		want        string
	}{
		{name: "valid", contentType: "application/json", body: `{"client_id":"` + publicID + `"}`, want: publicID},
		{name: "charset", contentType: "application/json; charset=utf-8", body: " { \n\"client_id\" : \"" + publicID + "\" } ", want: publicID},
		{name: "missing", contentType: "application/json", body: `{}`},
		{name: "duplicate", contentType: "application/json", body: `{"client_id":"` + publicID + `","client_id":"` + publicID + `"}`},
		{name: "extra", contentType: "application/json", body: `{"client_id":"` + publicID + `","user_id":"x"}`},
		{name: "wrong type", contentType: "application/json", body: `{"client_id":1}`},
		{name: "array", contentType: "application/json", body: `[]`},
		{name: "trailing", contentType: "application/json", body: `{"client_id":"` + publicID + `"}{}`},
		{name: "wrong content type", contentType: "text/plain", body: `{"client_id":"` + publicID + `"}`},
		{name: "oversized", contentType: "application/json", body: `{"client_id":"` + strings.Repeat("a", maxGrantMutationBodyBytes) + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, "/api/v1/me/grants/revoke", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			got, err := decodeGrantRevokeJSON(httptest.NewRecorder(), request)
			if test.want == "" && err == nil {
				t.Fatalf("got=%q, expected rejection", got)
			}
			if test.want != "" && (err != nil || got != test.want) {
				t.Fatalf("got=%q error=%v want=%q", got, err, test.want)
			}
		})
	}
}

func TestParseGrantPageUsesStrictVersionedCursorAndBounds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 1, 2, 3, 0, time.UTC)
	cursor := consent.EncodeGrantCursor(consent.GrantCursor{UpdatedAt: now, ClientID: httpGrantClientID(2)})
	valid := httptest.NewRequest(http.MethodGet, "/api/v1/me/grants?cursor="+cursor+"&limit=100", nil)
	gotCursor, limit, err := parseGrantPage(valid)
	if err != nil || gotCursor != cursor || limit != 100 {
		t.Fatalf("cursor=%q limit=%d error=%v", gotCursor, limit, err)
	}
	for _, target := range []string{
		"/api/v1/me/grants?limit=0",
		"/api/v1/me/grants?limit=01",
		"/api/v1/me/grants?limit=1&limit=2",
		"/api/v1/me/grants?unknown=1",
		"/api/v1/me/grants?cursor=bad",
		"/api/v1/me/grants?cursor=%zz",
	} {
		if _, _, err := parseGrantPage(httptest.NewRequest(http.MethodGet, target, nil)); err == nil {
			t.Errorf("target %q unexpectedly accepted", target)
		}
	}
}

func httpGrantClientID(fill byte) string {
	value := make([]byte, 24)
	for index := range value {
		value[index] = fill
	}
	return "ois_cli_" + base64.RawURLEncoding.EncodeToString(value)
}
