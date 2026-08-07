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
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	exampleSessionTTL           = time.Hour
	exampleSessionSweepInterval = time.Minute
	maxExampleSessions          = 1024
	pendingAuthTTL              = 10 * time.Minute
	pendingLogoutTTL            = 10 * time.Minute
	maxCallbackQuery            = 8 << 10
	maxMutationForm             = 4 << 10
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
	ID                 string
	CSRFToken          string
	Revision           uint64
	Pending            *authorizationAttempt
	Identity           *jitIdentity
	AccessToken        string
	RefreshToken       string
	RefreshVersion     uint64
	RefreshInFlight    uint64
	IDToken            string
	GrantedScopes      []string
	PendingLogoutState string
	PendingLogoutAt    time.Time
	ExpiresAt          time.Time
}

type memorySessions struct {
	mu       sync.Mutex
	randomMu sync.Mutex
	sessions map[string]browserSession
	random   io.Reader

	nextSweep time.Time
}

type refreshAttempt struct {
	SessionID    string
	Version      uint64
	RefreshToken string
	Scopes       []string
}

func newMemorySessions(randomSource io.Reader) *memorySessions {
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &memorySessions{sessions: make(map[string]browserSession), random: randomSource}
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
	id, err := s.newOpaque("exs1_", 32)
	if err != nil {
		return browserSession{}, err
	}
	csrf, err := s.newOpaque("csrf_", 32)
	if err != nil {
		return browserSession{}, err
	}
	value := browserSession{ID: id, CSRFToken: csrf, Revision: 1, ExpiresAt: now.Add(exampleSessionTTL)}
	s.mu.Lock()
	s.pruneLocked(now)
	if len(s.sessions) >= maxExampleSessions {
		s.mu.Unlock()
		return browserSession{}, errors.New("example session capacity is full")
	}
	if _, exists := s.sessions[id]; exists {
		s.mu.Unlock()
		return browserSession{}, errors.New("example session identifier collision")
	}
	s.sessions[id] = value
	s.mu.Unlock()
	return value, nil
}

func (s *memorySessions) save(value browserSession, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[value.ID]
	if !exists || !now.Before(current.ExpiresAt) || value.ID == "" || !now.Before(value.ExpiresAt) ||
		value.Revision != current.Revision {
		return errors.New("example session is no longer current")
	}
	value.Revision++
	s.sessions[value.ID] = cloneBrowserSession(value)
	return nil
}

// beginAuthorization updates only the pending authorization fields. In
// particular, a snapshot read before a concurrent refresh or logout cannot
// restore old protocol credentials or logout state.
func (s *memorySessions) beginAuthorization(id string, attempt authorizationAttempt, now time.Time) (browserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[id]
	if !exists || !now.Before(current.ExpiresAt) || attempt.State == "" || attempt.Nonce == "" || attempt.Verifier == "" {
		return browserSession{}, errors.New("example session is no longer current")
	}
	attemptCopy := attempt
	current.Pending = &attemptCopy
	current.ExpiresAt = now.Add(exampleSessionTTL)
	current.Revision++
	s.sessions[id] = cloneBrowserSession(current)
	return cloneBrowserSession(current), nil
}

func (s *memorySessions) complete(old browserSession, identity jitIdentity, now time.Time) (browserSession, error) {
	return s.completeWithTokens(old, identity, tokenResponse{}, now)
}

func (s *memorySessions) completeWithTokens(old browserSession, identity jitIdentity, tokens tokenResponse, now time.Time) (browserSession, error) {
	newID, err := s.newOpaque("exs1_", 32)
	if err != nil {
		return browserSession{}, err
	}
	csrf, err := s.newOpaque("csrf_", 32)
	if err != nil {
		return browserSession{}, err
	}
	identityCopy := identity
	value := browserSession{
		ID: newID, CSRFToken: csrf, Revision: 1, Identity: &identityCopy, AccessToken: tokens.AccessToken,
		RefreshToken: tokens.RefreshToken, IDToken: tokens.IDToken,
		GrantedScopes: append([]string(nil), tokens.GrantedScopes...), ExpiresAt: now.Add(exampleSessionTTL),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[old.ID]
	if !exists || !sameAuthorizationAttempt(current.Pending, old.Pending) {
		return browserSession{}, errors.New("example authorization attempt is no longer current")
	}
	if _, exists := s.sessions[newID]; exists {
		return browserSession{}, errors.New("example session identifier collision")
	}
	delete(s.sessions, old.ID)
	s.sessions[newID] = value
	return cloneBrowserSession(value), nil
}

func (s *memorySessions) clearPending(old browserSession, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[old.ID]
	if !exists || !sameAuthorizationAttempt(current.Pending, old.Pending) {
		return errors.New("example authorization attempt is no longer current")
	}
	current.Pending = nil
	current.Revision++
	s.sessions[old.ID] = current
	return nil
}

// claimRefresh marks one generation in flight before the Refresh Token leaves
// the process. A second browser request is rejected locally and never reaches
// the Provider.
func (s *memorySessions) claimRefresh(id, csrf string, now time.Time) (refreshAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[id]
	if !exists || !now.Before(current.ExpiresAt) || current.Identity == nil || current.RefreshToken == "" ||
		current.CSRFToken == "" || subtle.ConstantTimeCompare([]byte(current.CSRFToken), []byte(csrf)) != 1 ||
		current.RefreshInFlight != 0 {
		return refreshAttempt{}, errors.New("example refresh attempt cannot be claimed")
	}
	current.RefreshVersion++
	if current.RefreshVersion == 0 {
		return refreshAttempt{}, errors.New("example refresh generation is exhausted")
	}
	current.RefreshInFlight = current.RefreshVersion
	current.Revision++
	s.sessions[id] = cloneBrowserSession(current)
	return refreshAttempt{
		SessionID: id, Version: current.RefreshVersion, RefreshToken: current.RefreshToken,
		Scopes: append([]string(nil), current.GrantedScopes...),
	}, nil
}

// replaceRefresh commits a response only if it belongs to the claimed
// generation. A late response cannot overwrite a newer authorization result.
func (s *memorySessions) replaceRefresh(attempt refreshAttempt, response tokenResponse, now time.Time) (browserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[attempt.SessionID]
	if !exists || !now.Before(current.ExpiresAt) || attempt.Version == 0 ||
		current.RefreshVersion != attempt.Version || current.RefreshInFlight != attempt.Version {
		return browserSession{}, errors.New("example refresh attempt is no longer current")
	}
	current.AccessToken = response.AccessToken
	current.RefreshToken = response.RefreshToken
	current.GrantedScopes = append([]string(nil), response.GrantedScopes...)
	current.RefreshInFlight = 0
	current.Revision++
	s.sessions[attempt.SessionID] = cloneBrowserSession(current)
	return cloneBrowserSession(current), nil
}

// failRefresh discards local protocol authority only for the generation whose
// Provider outcome is invalid or ambiguous. It cannot erase a later result.
func (s *memorySessions) failRefresh(attempt refreshAttempt, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[attempt.SessionID]
	if !exists || !now.Before(current.ExpiresAt) || attempt.Version == 0 ||
		current.RefreshVersion != attempt.Version || current.RefreshInFlight != attempt.Version {
		return errors.New("example refresh attempt is no longer current")
	}
	current.AccessToken, current.RefreshToken, current.GrantedScopes = "", "", nil
	current.RefreshInFlight = 0
	current.Revision++
	s.sessions[attempt.SessionID] = cloneBrowserSession(current)
	return nil
}

// beginLogout binds a fresh provider-return state to the current server-side
// Session. The clear ID Token Hint remains in the Session and is never placed in
// the RP URL or browser cookie.
func (s *memorySessions) beginLogout(id, idToken, csrf, state string, now time.Time) (browserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[id]
	if !exists || !now.Before(current.ExpiresAt) || current.Identity == nil || current.IDToken == "" ||
		idToken == "" || subtle.ConstantTimeCompare([]byte(current.IDToken), []byte(idToken)) != 1 ||
		current.CSRFToken == "" || subtle.ConstantTimeCompare([]byte(current.CSRFToken), []byte(csrf)) != 1 || state == "" {
		return browserSession{}, errors.New("example logout session is no longer current")
	}
	current.PendingLogoutState = state
	current.PendingLogoutAt = now
	current.Revision++
	s.sessions[id] = cloneBrowserSession(current)
	return cloneBrowserSession(current), nil
}

// finishLogout consumes the exact state generated by beginLogout. A stale or
// cross-session callback cannot destroy a newer local Session.
func (s *memorySessions) finishLogout(id, state string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	current, exists := s.sessions[id]
	if !exists || !now.Before(current.ExpiresAt) || current.PendingLogoutState == "" ||
		current.PendingLogoutAt.IsZero() || !now.Before(current.PendingLogoutAt.Add(pendingLogoutTTL)) ||
		subtle.ConstantTimeCompare([]byte(current.PendingLogoutState), []byte(state)) != 1 {
		return errors.New("example logout state is invalid")
	}
	delete(s.sessions, id)
	return nil
}

func (s *memorySessions) newOpaque(prefix string, size int) (string, error) {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	return randomOpaque(s.random, prefix, size)
}

func (s *memorySessions) pruneLocked(now time.Time) {
	if now.Before(s.nextSweep) && len(s.sessions) < maxExampleSessions {
		return
	}
	for id, value := range s.sessions {
		if !now.Before(value.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	s.nextSweep = now.Add(exampleSessionSweepInterval)
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
	cloned.GrantedScopes = append([]string(nil), value.GrantedScopes...)
	return cloned
}

func sameAuthorizationAttempt(left, right *authorizationAttempt) bool {
	return left != nil && right != nil && left.State == right.State && left.Nonce == right.Nonce &&
		left.Verifier == right.Verifier && left.CreatedAt.Equal(right.CreatedAt)
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
	if _, err := parsed.New("logout").Parse(logoutTemplate); err != nil {
		return nil, errors.New("example logout template is invalid")
	}
	return &exampleApplication{config: cfg, metadata: metadata, client: client, sessions: sessions, now: time.Now, template: parsed}, nil
}

func (a *exampleApplication) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setExampleSecurityHeaders(writer.Header(), a.metadata.EndSessionEndpoint)
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
	case "/refresh":
		a.refresh(writer, request)
	case "/logout":
		a.logout(writer, request)
	case "/logged-out":
		a.loggedOut(writer, request)
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
		Name       string
		Issuer     string
		Identity   *jitIdentity
		CSRFToken  string
		Error      bool
		CanCreate  bool
		CanRefresh bool
	}{
		Name: a.config.Name, Issuer: a.metadata.Issuer, Identity: value.Identity, CSRFToken: value.CSRFToken,
		Error:      request.URL.Query().Get("result") != "",
		CanCreate:  slicesContainsString(a.metadata.PromptValuesSupported, "create"),
		CanRefresh: value.RefreshToken != "" && value.RefreshInFlight == 0,
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
	state, err := a.sessions.newOpaque("state_", 32)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	nonce, err := a.sessions.newOpaque("nonce_", 32)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	verifier, err := a.sessions.newOpaque("", 32)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256([]byte(verifier))
	bound, err := a.sessions.beginAuthorization(sessionValue.ID, authorizationAttempt{
		State: state, Nonce: nonce, Verifier: verifier, CreatedAt: now,
	}, now)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	a.setSessionCookie(writer, bound.ID)
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
		if err := a.sessions.clearPending(sessionValue, a.now().UTC()); err != nil {
			exampleError(writer, http.StatusBadRequest)
			return
		}
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
	claims, err := verifyIDToken(ctx, a.client, a.config, a.metadata, tokens.IDToken, pending.Nonce, tokens.GrantedScopes, a.now().UTC())
	if err != nil {
		log.Print("OIDC example callback rejected an ID Token")
		if revokeErr := revokeProviderTokens(ctx, a.client, a.config, a.metadata, tokens); revokeErr != nil {
			log.Print("OIDC example callback orphan revocation failed")
		}
		exampleError(writer, http.StatusBadGateway)
		return
	}
	userinfo, err := fetchUserInfo(ctx, a.client, a.config, a.metadata, tokens.AccessToken, claims.Subject, tokens.GrantedScopes)
	if err != nil {
		log.Print("OIDC example callback rejected UserInfo")
		if revokeErr := revokeProviderTokens(ctx, a.client, a.config, a.metadata, tokens); revokeErr != nil {
			log.Print("OIDC example callback orphan revocation failed")
		}
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
	rotated, err := a.sessions.completeWithTokens(sessionValue, identity, tokens, a.now().UTC())
	if err != nil {
		if revokeErr := revokeProviderTokens(ctx, a.client, a.config, a.metadata, tokens); revokeErr != nil {
			log.Print("OIDC example callback orphan revocation failed")
		}
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	a.setSessionCookie(writer, rotated.ID)
	writer.Header().Set("Location", "/")
	writer.WriteHeader(http.StatusSeeOther)
}

func (a *exampleApplication) refresh(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		exampleMethodNotAllowed(writer, http.MethodPost)
		return
	}
	csrf, ok := a.mutationCSRF(writer, request)
	if !ok {
		return
	}
	sessionValue, ok := a.readSession(request)
	if !ok || sessionValue.Identity == nil || sessionValue.RefreshToken == "" {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	attempt, err := a.sessions.claimRefresh(sessionValue.ID, csrf, a.now().UTC())
	if err != nil {
		exampleError(writer, http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	response, err := exchangeRefreshToken(ctx, a.client, a.config, a.metadata, attempt.RefreshToken, attempt.Scopes)
	if err != nil {
		if failErr := a.sessions.failRefresh(attempt, a.now().UTC()); failErr != nil {
			exampleError(writer, http.StatusConflict)
			return
		}
		if errors.Is(err, errProviderInvalidGrant) {
			http.Redirect(writer, request, "/login?prompt=login", http.StatusSeeOther)
			return
		}
		http.Redirect(writer, request, "/?result=reauthorization_required", http.StatusSeeOther)
		return
	}
	if _, err := a.sessions.replaceRefresh(attempt, response, a.now().UTC()); err != nil {
		if revokeErr := revokeProviderTokens(ctx, a.client, a.config, a.metadata, response); revokeErr != nil {
			log.Print("OIDC example refresh orphan revocation failed")
		}
		exampleError(writer, http.StatusConflict)
		return
	}
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

// logout renders the default RP-Initiated Logout form. A browser POST is used
// because the ID Token Hint and state must not appear in a redirect URL.
func (a *exampleApplication) logout(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		exampleMethodNotAllowed(writer, http.MethodPost)
		return
	}
	csrf, ok := a.mutationCSRF(writer, request)
	if !ok {
		return
	}
	sessionValue, ok := a.readSession(request)
	if !ok || sessionValue.Identity == nil || sessionValue.IDToken == "" || a.metadata.EndSessionEndpoint == "" || a.config.PostLogoutRedirectURI == "" {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	state, err := a.sessions.newOpaque("logout_", 32)
	if err != nil {
		exampleError(writer, http.StatusInternalServerError)
		return
	}
	bound, err := a.sessions.beginLogout(sessionValue.ID, sessionValue.IDToken, csrf, state, a.now().UTC())
	if err != nil {
		exampleError(writer, http.StatusConflict)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_ = a.template.ExecuteTemplate(writer, "logout", struct {
		Action                string
		ClientID              string
		IDTokenHint           string
		PostLogoutRedirectURI string
		State                 string
	}{
		Action: a.metadata.EndSessionEndpoint, ClientID: a.config.ClientID,
		IDTokenHint: bound.IDToken, PostLogoutRedirectURI: a.config.PostLogoutRedirectURI,
		State: bound.PendingLogoutState,
	})
}

// loggedOut is the only authority-destroying RP callback. It consumes the
// server-side state before replacing the cookie and redirecting to a clean URL.
func (a *exampleApplication) loggedOut(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.RawQuery == "" {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(values) != 1 || len(values["state"]) != 1 {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	state := values.Get("state")
	if len(state) > 128 || !strings.HasPrefix(state, "logout_") {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	sessionValue, ok := a.readSession(request)
	if !ok || sessionValue.Identity == nil {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	if err := a.sessions.finishLogout(sessionValue.ID, state, a.now().UTC()); err != nil {
		exampleError(writer, http.StatusBadRequest)
		return
	}
	a.clearSessionCookie(writer)
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("Location", "/")
	writer.WriteHeader(http.StatusSeeOther)
}

// mutationCSRF accepts only a small same-origin form containing one Session-
// bound token. Validation finishes before a caller can reach the Provider.
func (a *exampleApplication) mutationCSRF(writer http.ResponseWriter, request *http.Request) (string, bool) {
	if request.URL.RawQuery != "" || request.ContentLength <= 0 || request.ContentLength > maxMutationForm ||
		!sameOriginMutation(request, a.config.RedirectURI) || len(request.Header.Values("Content-Type")) != 1 {
		exampleError(writer, http.StatusBadRequest)
		return "", false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
		exampleError(writer, http.StatusBadRequest)
		return "", false
	}
	encoded, err := io.ReadAll(io.LimitReader(request.Body, maxMutationForm+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxMutationForm {
		exampleError(writer, http.StatusBadRequest)
		return "", false
	}
	values, err := url.ParseQuery(string(encoded))
	if err != nil || len(values) != 1 || len(values["csrf_token"]) != 1 {
		exampleError(writer, http.StatusBadRequest)
		return "", false
	}
	csrf := values.Get("csrf_token")
	if len(csrf) > 128 || !strings.HasPrefix(csrf, "csrf_") {
		exampleError(writer, http.StatusBadRequest)
		return "", false
	}
	return csrf, true
}

func sameOriginMutation(request *http.Request, callback string) bool {
	expected, err := url.Parse(callback)
	if err != nil || !expected.IsAbs() || expected.Host == "" {
		return false
	}
	found := false
	origins := request.Header.Values("Origin")
	if len(origins) > 1 {
		return false
	}
	if len(origins) == 1 {
		origin, parseErr := url.Parse(origins[0])
		if parseErr != nil || !origin.IsAbs() || origin.Host == "" || origin.User != nil || origin.Opaque != "" ||
			(origin.Path != "" && origin.Path != "/") || origin.RawPath != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
			!sameURLOrigin(origin, expected) {
			return false
		}
		found = true
	}
	referers := request.Header.Values("Referer")
	if len(referers) > 1 {
		return false
	}
	if len(referers) == 1 {
		referer, parseErr := url.Parse(referers[0])
		if parseErr != nil || !referer.IsAbs() || referer.Host == "" || referer.User != nil || referer.Opaque != "" ||
			referer.Fragment != "" || !sameURLOrigin(referer, expected) {
			return false
		}
		found = true
	}
	return found
}

func sameURLOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectiveURLPort(left) == effectiveURLPort(right)
}

func effectiveURLPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(value.Scheme, "http") {
		return "80"
	}
	return ""
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

func (a *exampleApplication) clearSessionCookie(writer http.ResponseWriter) {
	// #nosec G124 -- all cookie defenses are set below; Secure is configurable
	// only so the validated loopback HTTP interoperability profile can run.
	http.SetCookie(writer, &http.Cookie{
		Name: a.config.CookieName, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0).UTC(), HttpOnly: true, Secure: a.config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func setExampleSecurityHeaders(header http.Header, formActions ...string) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	formAction := "'self'"
	for _, raw := range formActions {
		parsed, err := url.Parse(raw)
		if err == nil && parsed.IsAbs() && parsed.Host != "" && parsed.User == nil && parsed.Fragment == "" {
			origin := parsed.Scheme + "://" + parsed.Host
			if !strings.Contains(formAction, origin) {
				formAction += " " + origin
			}
		}
	}
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; base-uri 'none'; frame-ancestors 'none'")
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
{{if .Identity}}<p>Signed in as <strong>{{.Identity.Name}}</strong>.</p><p>This example linked the account by the verified <code>(iss, sub)</code> pair.</p>{{if .CanRefresh}}<form method="post" action="/refresh"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button type="submit">Refresh server-side session</button></form>{{end}}<form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button type="submit">Sign out</button></form>
{{else}}<p>This interoperability example keeps state, nonce, and the PKCE verifier on the server and validates the signed ID Token before calling UserInfo.</p>
<a href="/login">Sign in</a>{{if .CanCreate}}<a href="/login?prompt=create">Create account</a>{{end}}{{end}}
</body></html>`

const logoutTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign out</title></head><body><main><h1>Sign out</h1>
<p>Continue to the Provider to finish signing out.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="id_token_hint" value="{{.IDTokenHint}}">
<input type="hidden" name="post_logout_redirect_uri" value="{{.PostLogoutRedirectURI}}">
<input type="hidden" name="state" value="{{.State}}">
<button type="submit">Continue</button>
</form></main></body></html>`
