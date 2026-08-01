package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"sync/atomic"
	"time"
)

const requestIDHeader = "X-Request-ID"

var (
	requestIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	requestIDFallback atomic.Uint64
)

type requestIDContextKey struct{}

// ValidRequestID validates the bounded external request-ID contract.
func ValidRequestID(value string) bool {
	return requestIDPattern.MatchString(value)
}

// RequestID returns the request ID injected by the outer middleware.
func RequestID(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	return requestID
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := ""
		values := request.Header.Values(requestIDHeader)
		if len(values) == 1 && ValidRequestID(values[0]) {
			requestID = values[0]
		}
		if requestID == "" {
			requestID = newRequestID()
		}

		writer.Header().Set(requestIDHeader, requestID)
		ctx := context.WithValue(request.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func newRequestID() string {
	random := make([]byte, 18)
	if _, err := rand.Read(random); err == nil {
		return "req_" + base64.RawURLEncoding.EncodeToString(random)
	}

	seed := fmt.Sprintf("%d:%d", time.Now().UnixNano(), requestIDFallback.Add(1))
	digest := sha256.Sum256([]byte(seed))
	return "req_" + base64.RawURLEncoding.EncodeToString(digest[:18])
}
