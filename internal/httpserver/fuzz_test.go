package httpserver

import (
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
