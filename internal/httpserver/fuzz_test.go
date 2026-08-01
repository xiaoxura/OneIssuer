package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzAuthenticationFormParsing(f *testing.F) {
	f.Add("csrf_token=a&transaction=b&identifier=c&password=d", "application/x-www-form-urlencoded")
	f.Add("csrf_token=a&transaction=b&identifier=c&identifier=d&password=e", "application/x-www-form-urlencoded")
	f.Add("return_to=https%3A%2F%2Fexample.invalid", "application/x-www-form-urlencoded")
	f.Add("%zz", "application/x-www-form-urlencoded")
	f.Add("{}", "application/json")

	f.Fuzz(func(t *testing.T, body, contentType string) {
		if len(body) > 128<<10 || len(contentType) > 256 {
			t.Skip()
		}
		request := httptest.NewRequest("POST", "/login", strings.NewReader(body))
		request.Header.Set("Content-Type", contentType)
		response := httptest.NewRecorder()
		form, err := parseAuthForm(response, request, "csrf_token", "transaction", "identifier", "password")
		if err != nil {
			return
		}
		for _, key := range []string{"csrf_token", "transaction", "identifier", "password"} {
			if len(form[key]) != 1 {
				t.Fatalf("successful parse did not produce exactly one %s", key)
			}
		}
		if len(form) != 4 {
			t.Fatal("successful parse retained an unknown field")
		}
	})
}

func FuzzTokenFormParsing(f *testing.F) {
	f.Add(validHTTPTokenForm().Encode(), "application/x-www-form-urlencoded", "")
	f.Add("grant_type=authorization_code&code=%GG", "application/x-www-form-urlencoded", "")
	f.Add(strings.Repeat("x", maxTokenBodyBytes+1), "application/x-www-form-urlencoded", "")
	f.Add("grant_type=refresh_token", "application/json", "access_token=canary")

	f.Fuzz(func(t *testing.T, body, contentType, rawQuery string) {
		if len(body) > 128<<10 || len(contentType) > 512 || len(rawQuery) > 16<<10 {
			t.Skip()
		}
		request := httptest.NewRequest(http.MethodPost, oidcTokenFuzzPath, strings.NewReader(body))
		request.URL.RawQuery = rawQuery
		request.Header["Content-Type"] = []string{contentType}
		response := httptest.NewRecorder()
		values, err := parseTokenForm(response, request)
		if err == nil && (len(values) == 0 || len(body) > maxTokenBodyBytes || rawQuery != "") {
			t.Fatalf("unsafe token form accepted: body_len=%d query_len=%d", len(body), len(rawQuery))
		}
	})
}

func FuzzUserInfoBearerParsing(f *testing.F) {
	f.Add("Bearer header.payload.signature", "", "")
	f.Add("Basic canary", "", "")
	f.Add("Bearer header.payload.signature,Bearer second.payload.signature", "", "")
	f.Add("Bearer header.payload.signature", "access_token=canary", "")

	f.Fuzz(func(t *testing.T, authorizationHeader, body, rawQuery string) {
		if len(authorizationHeader) > 128<<10 || len(body) > 128<<10 || len(rawQuery) > 16<<10 {
			t.Skip()
		}
		request := httptest.NewRequest(http.MethodPost, oidcUserInfoFuzzPath, strings.NewReader(body))
		request.URL.RawQuery = rawQuery
		request.Header["Authorization"] = []string{authorizationHeader}
		compact, err := parseUserInfoBearer(httptest.NewRecorder(), request)
		if err == nil {
			if body != "" || rawQuery != "" || compact == "" || len(compact) > maxBearerTokenBytes || strings.Count(compact, ".") != 2 {
				t.Fatalf("unsafe Bearer input accepted: compact_len=%d", len(compact))
			}
		}
	})
}

const (
	oidcTokenFuzzPath    = "/oauth2/token"
	oidcUserInfoFuzzPath = "/oauth2/userinfo"
)
