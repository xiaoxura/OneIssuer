package httpserver

import (
	"net/http"
	"strings"
)

const (
	jwksCacheControl      = "public, max-age=300"
	discoveryCacheControl = "public, max-age=300"
)

func (a *applicationHandler) handleDiscovery(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}
	writer.Header().Set("Cache-Control", discoveryCacheControl)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	// #nosec G705 -- metadata is startup-built JSON from a validated canonical
	// Issuer and fixed constant capability lists, not request-derived HTML.
	_, _ = writer.Write(a.metadata)
}

func (a *applicationHandler) handleJWKS(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}

	encoded := a.publicKeys.PublicJWKS()
	etag := a.publicKeys.ETag()
	if len(encoded) == 0 || etag == "" {
		writeError(writer, request, http.StatusServiceUnavailable, "temporarily_unavailable", "service temporarily unavailable")
		return
	}

	writer.Header().Set("Cache-Control", jwksCacheControl)
	writer.Header().Set("ETag", etag)
	if ifNoneMatch(strings.Join(request.Header.Values("If-None-Match"), ","), etag) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	// #nosec G705 -- encoded is immutable JSON serialized from validated public
	// JWKs; the handler sets application/json and never renders it as HTML.
	_, _ = writer.Write(encoded)
}

// If-None-Match uses weak comparison for GET as required by HTTP semantics. The
// generated ETag itself remains strong and derives only from public bytes.
func ifNoneMatch(headerValue, current string) bool {
	current = strings.TrimPrefix(strings.TrimSpace(current), "W/")
	if current == "" {
		return false
	}
	for _, candidate := range strings.Split(headerValue, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == current {
			return true
		}
	}
	return false
}
