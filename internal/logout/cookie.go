package logout

import (
	"net/http"
	"strings"
	"time"
)

// ConfirmPath is the restricted path used by the transient logout cookie.
const ConfirmPath = "/oauth2/logout/confirm"

// CookieManager carries only the short-lived transaction lookup value. It is
// host-only and deliberately uses a restricted Path unlike the main Session.
type CookieManager struct {
	Name   string
	Secure bool
	TTL    time.Duration
}

// NewCookieManager derives a distinct name without the __Host- prefix because
// that prefix mandates Path=/ and is incompatible with the restricted Path.
func NewCookieManager(sessionCookieName string, secure bool, ttl time.Duration) CookieManager {
	stem := strings.TrimPrefix(strings.TrimPrefix(sessionCookieName, "__Host-"), "__Secure-")
	name := stem + "_logout_transaction"
	if secure {
		name = "__Secure-" + name
	}
	return CookieManager{Name: name, Secure: secure, TTL: ttl}
}

// Set emits the dedicated HttpOnly SameSite=Lax continuation cookie.
func (m CookieManager) Set(writer http.ResponseWriter, value string) {
	http.SetCookie(writer, m.cookie(value, boundedCookieAge(m.TTL)))
}

// Clear terminally removes the cookie with identical security/path attributes.
func (m CookieManager) Clear(writer http.ResponseWriter) {
	// #nosec G124 -- cookie() sets fixed HttpOnly/SameSite/Path attributes.
	cookie := m.cookie("", -1)
	cookie.Expires = time.Unix(1, 0).UTC()
	http.SetCookie(writer, cookie)
}

// Token returns the clear lookup token only at the browser boundary.
func (m CookieManager) Token(request *http.Request) string {
	cookie, err := request.Cookie(m.Name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (m CookieManager) cookie(value string, maxAge int) *http.Cookie {
	// #nosec G124 -- fixed HttpOnly/SameSite/Path attributes are intentional.
	return &http.Cookie{
		Name: m.Name, Value: value, Path: ConfirmPath, Secure: m.Secure,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	}
}

func boundedCookieAge(ttl time.Duration) int {
	seconds := int(ttl.Seconds())
	if seconds < 1 {
		return 1
	}
	return seconds
}
