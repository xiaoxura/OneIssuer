package session

import (
	"net/http"
	"strings"
	"time"
)

// CookieManager is the only component that emits authentication cookies.
type CookieManager struct {
	SessionName string
	PreAuthName string
	CSRFName    string
	Secure      bool
	SessionTTL  time.Duration
	PreAuthTTL  time.Duration
}

// NewCookieManager derives pre-auth and CSRF cookie names from the session name.
func NewCookieManager(sessionName string, secure bool, sessionTTL, preAuthTTL time.Duration) CookieManager {
	stem := sessionName
	prefix := ""
	if strings.HasPrefix(stem, "__Host-") {
		prefix = "__Host-"
		stem = strings.TrimPrefix(stem, prefix)
	}
	return CookieManager{
		SessionName: sessionName,
		PreAuthName: prefix + stem + "_preauth",
		CSRFName:    prefix + stem + "_csrf",
		Secure:      secure,
		SessionTTL:  sessionTTL,
		PreAuthTTL:  preAuthTTL,
	}
}

// SetAuthenticated emits a session cookie and readable double-submit CSRF cookie.
func (m CookieManager) SetAuthenticated(writer http.ResponseWriter, issued Issued) {
	http.SetCookie(writer, m.cookie(m.SessionName, issued.Token, true, http.SameSiteLaxMode, m.SessionTTL))
	http.SetCookie(writer, m.cookie(m.CSRFName, issued.CSRFToken, false, http.SameSiteStrictMode, m.PreAuthTTL))
	m.clear(writer, m.PreAuthName, true, http.SameSiteLaxMode)
}

// SetPreAuth emits the HttpOnly cookie for a browser authentication form flow.
func (m CookieManager) SetPreAuth(writer http.ResponseWriter, issued IssuedPreAuth) {
	http.SetCookie(writer, m.cookie(m.PreAuthName, issued.Token, true, http.SameSiteLaxMode, m.PreAuthTTL))
}

// SetCSRF emits a rotated readable CSRF cookie.
func (m CookieManager) SetCSRF(writer http.ResponseWriter, token string) {
	http.SetCookie(writer, m.cookie(m.CSRFName, token, false, http.SameSiteStrictMode, m.PreAuthTTL))
}

// ClearAuthenticated expires both authenticated-session cookies.
func (m CookieManager) ClearAuthenticated(writer http.ResponseWriter) {
	m.clear(writer, m.SessionName, true, http.SameSiteLaxMode)
	m.clear(writer, m.CSRFName, false, http.SameSiteStrictMode)
}

// ClearPreAuth expires the pre-authentication cookie.
func (m CookieManager) ClearPreAuth(writer http.ResponseWriter) {
	m.clear(writer, m.PreAuthName, true, http.SameSiteLaxMode)
}

func (m CookieManager) cookie(name, value string, httpOnly bool, sameSite http.SameSite, ttl time.Duration) *http.Cookie {
	seconds := int(ttl.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	// #nosec G124 -- each caller supplies the appropriate HttpOnly/SameSite pair;
	// production configuration independently requires Secure=true.
	return &http.Cookie{
		Name: name, Value: value, Path: "/", Secure: m.Secure, HttpOnly: httpOnly,
		SameSite: sameSite, MaxAge: seconds,
	}
}

func (m CookieManager) clear(writer http.ResponseWriter, name string, httpOnly bool, sameSite http.SameSite) {
	// #nosec G124 -- the helper preserves the original cookie's security attributes.
	cookie := m.cookie(name, "", httpOnly, sameSite, time.Second)
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(1, 0).UTC()
	http.SetCookie(writer, cookie)
}

func cookieValue(request *http.Request, name string) string {
	cookie, err := request.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// SessionToken returns the clear session cookie value or an empty string.
func (m CookieManager) SessionToken(request *http.Request) string {
	return cookieValue(request, m.SessionName)
}

// PreAuthToken returns the clear pre-authentication cookie value or an empty string.
func (m CookieManager) PreAuthToken(request *http.Request) string {
	return cookieValue(request, m.PreAuthName)
}

// CSRFToken returns the readable CSRF cookie value or an empty string.
func (m CookieManager) CSRFToken(request *http.Request) string {
	return cookieValue(request, m.CSRFName)
}
