package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	exampleSessionTTL = time.Hour
	pendingAuthTTL    = 10 * time.Minute
	maxCallbackQuery  = 8 << 10
)

type authorizationAttempt struct {
	State     string
	Nonce     string
	Verifier  string
	CreatedAt time.Time
}

type jitIdentity struct {
	Key      string
	Issuer   string
	Subject  string
	Name     string
	SignedIn time.Time
}

type browserSession struct {
	ID        string
	Pending   *authorizationAttempt
	Identity  *jitIdentity
	ExpiresAt time.Time
}

type memorySessions struct {
	mu         sync.Mutex
	sessions   map[string]browserSession
	identities map[string]jitIdentity
	random     io.Reader
}

func newMemorySessions(randomSource io.Reader) *memorySessions {
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &memorySessions{sessions: make(map[string]browserSession), identities: make(map[string]jitIdentity), random: randomSource}
}

func (s *memorySessions) get(id string, now time.Time) (browserSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.sessions[id]
	if !ok || !now.Before(value.ExpiresAt) {
		delete(s.sessions, id)
		return browserSession{}, false
	}
	return cloneBrowserSession(value), true
}

func (s *memorySessions) create(now time.Time) (browserSession, error) {
	id, err := randomOpaque(s.random, "exs1_", 32)
	if err != nil {
		return browserSession{}, err
	}
	value := browserSession{ID: id, ExpiresAt: now.Add(exampleSessionTTL)}
	s.mu.Lock()
	s.sessions[id] = value
	s.mu.Unlock()
	return value, nil
}

func (s *memorySessions) save(value browserSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[value.ID] = cloneBrowserSession(value)
}

func (s *memorySessions) complete(old browserSession, identity jitIdentity, now time.Time) (browserSession, error) {
	newID, err := randomOpaque(s.random, "exs1_", 32)
	if err != nil {
		return browserSession{}, err
	}
	identityCopy := identity
	value := browserSession{ID: newID, Identity: &identityCopy, ExpiresAt: now.Add(exampleSessionTTL)}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, old.ID)
	s.identities[identity.Key] = identity
	s.sessions[newID] = value
	return cloneBrowserSession(value), nil
}

func cloneBrowserSession(value browserSession) browserSession {
	cloned := value
	if value.Pending != nil {
		pending := *value.Pending
		cloned.Pending = &pending
	}
	if value.Identity != nil {
		identity := *value.Identity
		cloned.Identity = &identity
	}
	return cloned
}

type exampleApplication struct {
	config   exampleConfig
	metadata providerMetadata
	client   *http.Client
	sessions *memorySessions
	now      func() time.Time
	template *template.Template
}

func newExampleApplication(cfg exampleConfig, metadata providerMetadata, client *http.Client, sessions *memorySessions) (*exampleApplication, error) {
	if client == nil || sessions == nil {
		return nil, errors.New("example application dependencies are incomplete")
	}
	parsed, err := template.New("home").Parse(homeTemplate)
	if err != nil {
		return nil, errors.New("example page template is invalid")
	}
	return &exampleApplication{config: cfg, metadata: metadata, client: client, sessions: sessions, now: time.Now, template: parsed}, nil
}

func (a *exampleApplication) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setExampleSecurityHeaders(writer.Header())
	switch request.URL.Path {
	case "/health/live", "/health/ready":
		if request.Method != http.MethodGet {
			exampleMethodNotAllowed(writer, http.MethodGet)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "{\"status\":\"ok\"}\n")
	case "/":
		a.home(writer, request)
	case "/login":
		a.beginLogin(writer, request)
	case "/callback":
		a.callback(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (a *exampleApplication) home(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		exampleMethodNotAllowed(writer, http.MethodGet)
		return
	}
	value, _ := a.readSession(request)
	data := struct {
		Name      string
		Issuer    string
		Identity  *jitIdentity
		Error     bool
		CanCreate bool
	}{
		Name: a.config.Name, Issuer: a.metadata.Issuer, Identity: value.Identity,
		Error:     request.URL.Query().Get("result") == "authorization_not_completed",
		CanCreate: slicesContainsString(a.metadata.PromptValuesSupported, "create"),
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_ = a.template.Execute(writer, data)
}

func (a *exampleApplication) beginLogin(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || len(request.URL.RawQuery) > maxCallbackQuery {
		if request.Method != http.MethodGet {
			exampleMethodNotAllowed(writer, http.MethodGet)
		} else {
			exampleError(writer, http.StatusBadRequest)
		}
		return
	}
	query := request.URL.Query()
	if len(query) > 1 || len(query["prompt"]) > 1 {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	prompt := query.Get("prompt")
	if !validExamplePrompt(prompt) {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	now := a.now().UTC()
	sessionValue, ok := a.readSession(request)
	if !ok {
		var err error
		sessionValue, err = a.sessions.create(now)
		if err != nil {
			exampleError(writer, http.StatusInternalServerError)
			return
		}
	}
	state, err := randomOpaque(a.sessions.random, "state_", 32)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	nonce, err := randomOpaque(a.sessions.random, "nonce_", 32)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	verifier, err := randomOpaque(a.sessions.random, "", 32)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256([]byte(verifier))
	sessionValue.Pending = &authorizationAttempt{State: state, Nonce: nonce, Verifier: verifier, CreatedAt: now}
	sessionValue.ExpiresAt = now.Add(exampleSessionTTL)
	a.sessions.save(sessionValue)
	a.setSessionCookie(writer, sessionValue.ID)
	authorize, err := url.Parse(a.metadata.AuthorizationEndpoint)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	parameters := url.Values{
		"client_id": {a.config.ClientID}, "redirect_uri": {a.config.RedirectURI},
		"response_type": {"code"}, "response_mode": {"query"}, "scope": {strings.Join(a.config.Scopes, " ")},
		"state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
	}
	if prompt != "" {
		parameters.Set("prompt", prompt)
	}
	authorize.RawQuery = parameters.Encode()
	writer.Header().Set("Location", authorize.String())
	writer.WriteHeader(http.StatusFound)
}

func (a *exampleApplication) callback(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || len(request.URL.RawQuery) == 0 || len(request.URL.RawQuery) > maxCallbackQuery {
		if request.Method != http.MethodGet {
			exampleMethodNotAllowed(writer, http.MethodGet)
		} else {
			exampleError(writer, http.StatusBadRequest)
		}
		return
	}
	sessionValue, ok := a.readSession(request)
	if !ok || sessionValue.Pending == nil || a.now().UTC().After(sessionValue.Pending.CreatedAt.Add(pendingAuthTTL)) {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	query := request.URL.Query()
	if len(query["state"]) != 1 || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(sessionValue.Pending.State)) != 1 {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	if len(query["error"]) == 1 && len(query) == 2 {
		sessionValue.Pending = nil
		a.sessions.save(sessionValue)
		writer.Header().Set("Location", "/?result=authorization_not_completed")
		writer.WriteHeader(http.StatusSeeOther)
		return
	}
	if len(query) != 2 || len(query["code"]) != 1 || query.Get("code") == "" {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	pending := *sessionValue.Pending
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	tokens, err := exchangeAuthorizationCode(ctx, a.client, a.config, a.metadata, query.Get("code"), pending.Verifier)
	if err != nil {
		log.Print("OIDC example callback failed during code exchange")
		exampleError(writer, http.StatusBadGateway)
		return
	}
	claims, err := verifyIDToken(ctx, a.client, a.config, a.metadata, tokens.IDToken, pending.Nonce, a.now().UTC())
	if err != nil {
		log.Print("OIDC example callback rejected an ID Token")
		exampleError(writer, http.StatusBadGateway)
		return
	}
	userinfo, err := fetchUserInfo(ctx, a.client, a.config, a.metadata, tokens.AccessToken, claims.Subject)
	if err != nil {
		log.Print("OIDC example callback rejected UserInfo")
		exampleError(writer, http.StatusBadGateway)
		return
	}
	name := claims.Subject
	if userinfo.Name != nil && *userinfo.Name != "" {
		name = *userinfo.Name
	}
	identity := jitIdentity{
		Key: jitIdentityKey(claims.Issuer, claims.Subject), Issuer: claims.Issuer,
		Subject: claims.Subject, Name: name, SignedIn: a.now().UTC(),
	}
	rotated, err := a.sessions.complete(sessionValue, identity, a.now().UTC())
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	a.setSessionCookie(writer, rotated.ID)
	writer.Header().Set("Location", "/")
	writer.WriteHeader(http.StatusSeeOther)
}

func (a *exampleApplication) readSession(request *http.Request) (browserSession, bool) {
	cookie, err := request.Cookie(a.config.CookieName)
	if err != nil || len(cookie.Value) > 128 || !strings.HasPrefix(cookie.Value, "exs1_") {
		return browserSession{}, false
	}
	return a.sessions.get(cookie.Value, a.now().UTC())
}

func (a *exampleApplication) setSessionCookie(writer http.ResponseWriter, value string) {
	// #nosec G124 -- all cookie defenses are set below; Secure is configurable
	// only so the validated loopback HTTP interoperability profile can run.
	http.SetCookie(writer, &http.Cookie{
		Name: a.config.CookieName, Value: value, Path: "/", MaxAge: int(exampleSessionTTL / time.Second),
		HttpOnly: true, Secure: a.config.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

func setExampleSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func exampleMethodNotAllowed(writer http.ResponseWriter, methods ...string) {
	writer.Header().Set("Allow", strings.Join(methods, ", "))
	exampleError(writer, http.StatusMethodNotAllowed)
}

func exampleError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, "request could not be completed\n")
}

func randomOpaque(source io.Reader, prefix string, size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", errors.New("secure random generation failed")
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func jitIdentityKey(issuer, subject string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return "jit1_" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func validExamplePrompt(value string) bool {
	switch value {
	case "", "create", "login", "consent", "login consent", "create consent":
		return true
	default:
		return false
	}
}

func slicesContainsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

const homeTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Name}}</title><style>body{font:16px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem}a{display:inline-block;margin:.5rem 1rem .5rem 0}.notice{padding:.75rem;background:#fff4d6}</style></head>
<body><h1>{{.Name}}</h1><p>Provider: <code>{{.Issuer}}</code></p>
{{if .Error}}<p class="notice">Authorization was not completed. Start a new request.</p>{{end}}
{{if .Identity}}<p>Signed in as <strong>{{.Identity.Name}}</strong>.</p><p>This example linked the account by the verified <code>(iss, sub)</code> pair.</p>
{{else}}<p>This interoperability example keeps state, nonce, and the PKCE verifier on the server and validates the signed ID Token before calling UserInfo.</p>
<a href="/login">Sign in</a>{{if .CanCreate}}<a href="/login?prompt=create">Create account</a>{{end}}{{end}}
</body></html>`
