// Package logout owns RP-Initiated Logout hint verification, digest-only
// transaction tokens, one-time confirmation proofs, and redirect policy. Browser
// Session and cross-authority SQL remain repository-owned.
package logout

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/session"
	tokendomain "github.com/oneissuer/oneissuer/internal/token"
)

const (
	lookupPrefix          = "lt1_"
	csrfPrefix            = "lc1_"
	maxCompactHintBytes   = 8 << 10
	maxIDTokenLifetime    = 15 * time.Minute
	maxTransactionTries   = 10
	maxStateBytes         = 1024
	maxRedirectURIBytes   = 2048
	maxHintSubjectBytes   = 255
	maxPublicClientIDSize = 128
)

var (
	// ErrInvalid identifies malformed internal input or configuration.
	ErrInvalid = errors.New("logout operation is invalid")
	// ErrNotFound deliberately merges missing, malformed, expired, terminal, and
	// wrong-Session transaction lookup failures at the browser boundary.
	ErrNotFound = errors.New("logout transaction is unavailable")
	// ErrCapacity indicates the frozen reject-current per-Session bind policy.
	ErrCapacity = errors.New("logout transaction capacity exceeded")
	// ErrCSRF merges stale, replayed, and mismatched confirmation proofs.
	ErrCSRF = errors.New("logout confirmation proof is invalid")
)

// Stage is the persisted logout transaction state machine.
type Stage string

// Decision is the only confirmation mutation accepted from the hosted form.
type Decision string

const (
	// StagePreConfirm is the zero-authority state before same-origin binding.
	StagePreConfirm Stage = "pre_confirm"
	// StageBoundConfirm is the state accepted by the hosted confirmation form.
	StageBoundConfirm Stage = "bound_confirmable"
	// StageConfirmed is the terminal state after authority revocation commits.
	StageConfirmed Stage = "confirmed"
	// StageCanceled is the terminal state after the user declines logout.
	StageCanceled Stage = "canceled"
	// DecisionConfirm accepts the hosted form's confirmation choice.
	DecisionConfirm Decision = "confirm"
	// DecisionCancel accepts the hosted form's cancellation choice.
	DecisionCancel Decision = "cancel"
)

// Transaction contains only digest and verified server-side authority. It never
// contains a clear lookup token, CSRF proof, ID Token Hint, or browser cookie.
type Transaction struct {
	ID                    uuid.UUID
	LookupHash            []byte
	Stage                 Stage
	CSRFHash              []byte
	VerifiedClientID      *uuid.UUID
	PostLogoutRedirectURI string
	State                 string
	HintSubject           string
	UserID                *uuid.UUID
	SessionID             *uuid.UUID
	SessionBindingID      *uuid.UUID
	CreatedAt             time.Time
	ExpiresAt             time.Time
	BoundAt               *time.Time
	ConsumedAt            *time.Time
	AttemptCount          int16
}

// StartInput is parser-validated standard RP Logout Request data. Hint, State,
// and ignored values remain transient and must never be logged.
type StartInput struct {
	IDTokenHint           string
	ClientID              string
	LogoutHint            string
	PostLogoutRedirectURI string
	State                 string
	UILocales             string
	Now                   time.Time
}

// Issued contains the clear lookup value solely for the transient cookie and its
// digest-only persisted transaction.
type Issued struct {
	LookupToken string
	Transaction Transaction
}

// BindInput binds a clean continuation to the exact authenticated Session.
type BindInput struct {
	LookupHash       []byte
	CSRFHash         []byte
	UserID           uuid.UUID
	SessionID        uuid.UUID
	SessionBindingID uuid.UUID
	Subject          string
	Now              time.Time
	MaxActive        int
	MaxAttempts      int16
}

// Bound is a confirmable hosted page context. The clear proof is emitted only in
// that page and is rotated on every successful GET.
type Bound struct {
	CSRFProof             string
	ExpiresAt             time.Time
	PostLogoutRedirectURI string
}

// CompleteInput contains only digest authority and the already-authenticated
// current Principal.
type CompleteInput struct {
	LookupHash       []byte
	CSRFHash         []byte
	Decision         Decision
	UserID           uuid.UUID
	SessionID        uuid.UUID
	SessionBindingID uuid.UUID
	Now              time.Time
	RequestID        string
	MaxAttempts      int16
}

// CompletionCandidate is returned only after a known commit. Redirect fields are
// still rechecked against the current Client registry by Service.Complete.
type CompletionCandidate struct {
	Confirmed             bool
	VerifiedClientID      *uuid.UUID
	PostLogoutRedirectURI string
	State                 string
}

// Completion is the final browser delivery decision.
type Completion struct {
	Confirmed bool
	Location  string
}

// Repository owns transaction stage locking and the atomic Session-binding,
// family, Access, and Audit mutation.
type Repository interface {
	CreateLogoutTransaction(context.Context, Transaction) error
	BindLogoutTransaction(context.Context, BindInput) (Transaction, error)
	CompleteLogoutTransaction(context.Context, CompleteInput) (CompletionCandidate, error)
}

// ClientResolver exposes only active credential-free Client records.
type ClientResolver interface {
	ResolveActive(context.Context, string) (clientdomain.Client, error)
	GetActive(context.Context, uuid.UUID) (clientdomain.Client, error)
}

// VerificationKeys cannot expose private key material.
type VerificationKeys interface {
	PublicKeys() []jose.JSONWebKey
}

// Metrics accepts only fixed RP logout outcome labels.
type Metrics interface {
	RPLogout(result string)
}

// Service implements the accepted Hint age/key policy and transaction lifecycle.
type Service struct {
	repository Repository
	clients    ClientResolver
	keys       VerificationKeys
	issuer     string
	ttl        time.Duration
	hintMaxAge time.Duration
	clockSkew  time.Duration
	maxActive  int
	random     io.Reader
	metrics    Metrics
}

// NewService creates the RP logout service. Random may be nil to use crypto/rand.
func NewService(repository Repository, clients ClientResolver, keys VerificationKeys, issuer string, ttl, hintMaxAge, clockSkew time.Duration, maxActive int, randomSource io.Reader, metrics ...Metrics) (*Service, error) {
	parsedIssuer, err := url.Parse(issuer)
	if repository == nil || clients == nil || keys == nil || err != nil || parsedIssuer.String() != issuer ||
		(parsedIssuer.Scheme != "http" && parsedIssuer.Scheme != "https") || parsedIssuer.Host == "" ||
		parsedIssuer.User != nil || parsedIssuer.Opaque != "" || parsedIssuer.Path != "" || parsedIssuer.RawPath != "" ||
		parsedIssuer.RawQuery != "" || parsedIssuer.ForceQuery || parsedIssuer.Fragment != "" ||
		ttl < time.Minute || ttl > 15*time.Minute || hintMaxAge < 5*time.Minute || hintMaxAge > 30*24*time.Hour ||
		clockSkew < 0 || clockSkew > 5*time.Minute || maxActive < 1 || maxActive > 5 {
		return nil, ErrInvalid
	}
	if randomSource == nil {
		randomSource = rand.Reader
	}
	service := &Service{
		repository: repository, clients: clients, keys: keys, issuer: issuer,
		ttl: ttl, hintMaxAge: hintMaxAge, clockSkew: clockSkew,
		maxActive: maxActive, random: randomSource,
	}
	if len(metrics) > 0 {
		service.metrics = metrics[0]
	}
	return service, nil
}

// Start verifies optional redirect authority, creates a zero-Session-authority
// transaction, and returns its clear lookup token only after persistence succeeds.
func (s *Service) Start(ctx context.Context, input StartInput) (Issued, error) {
	if !validStartInput(input) {
		s.observe("rejected")
		return Issued{}, ErrInvalid
	}
	lookup, lookupHash, err := newSecret(s.random, lookupPrefix, hashLookup)
	if err != nil {
		s.observe("failure")
		return Issued{}, err
	}
	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		s.observe("failure")
		return Issued{}, errors.New("logout transaction identifier generation failed")
	}
	now := input.Now.UTC()
	transaction := Transaction{
		ID: id, LookupHash: lookupHash, Stage: StagePreConfirm,
		CreatedAt: now, ExpiresAt: now.Add(s.ttl),
	}

	if claims, valid := s.verifyHint(input.IDTokenHint, now); valid &&
		(input.ClientID == "" || input.ClientID == claims.Audience) {
		clientValue, resolveErr := s.clients.ResolveActive(ctx, claims.Audience)
		switch {
		case resolveErr == nil && clientValue.ClientID == claims.Audience:
			clientID := clientValue.ID
			transaction.VerifiedClientID = &clientID
			transaction.HintSubject = claims.Subject
			if exactLogoutURI(clientValue, input.PostLogoutRedirectURI) &&
				(input.State == "" || !hasDecodedStateKey(input.PostLogoutRedirectURI)) {
				transaction.PostLogoutRedirectURI = input.PostLogoutRedirectURI
				transaction.State = input.State
			}
		case errors.Is(resolveErr, clientdomain.ErrNotFound):
			// An unknown/disabled Hint audience is a local-only logout, not an oracle.
		default:
			s.observe("failure")
			return Issued{}, resolveErr
		}
	}

	if err := s.repository.CreateLogoutTransaction(ctx, transaction); err != nil {
		s.observe("failure")
		return Issued{}, err
	}
	s.observe("started")
	return Issued{LookupToken: lookup, Transaction: transaction}, nil
}

// Bind is the only pre-confirm -> bound transition. It rotates a proof on reload
// and the repository enforces exact Session identity and reject-current capacity.
func (s *Service) Bind(ctx context.Context, lookup string, principal session.Principal, now time.Time) (Bound, error) {
	lookupHash, err := DigestLookupToken(lookup)
	if err != nil || !validPrincipal(principal) || now.IsZero() {
		s.observe("invalid")
		return Bound{}, ErrNotFound
	}
	proof, proofHash, err := newSecret(s.random, csrfPrefix, hashCSRF)
	if err != nil {
		s.observe("failure")
		return Bound{}, err
	}
	transaction, err := s.repository.BindLogoutTransaction(ctx, BindInput{
		LookupHash: lookupHash, CSRFHash: proofHash,
		UserID: principal.User.ID, SessionID: principal.SessionID,
		SessionBindingID: principal.SessionBindingID, Subject: principal.User.Subject,
		Now: now.UTC(), MaxActive: s.maxActive, MaxAttempts: maxTransactionTries,
	})
	if err != nil {
		if errors.Is(err, ErrCapacity) {
			s.observe("capacity")
		} else if errors.Is(err, ErrNotFound) {
			s.observe("invalid")
		} else {
			s.observe("failure")
		}
		return Bound{}, err
	}
	if transaction.Stage != StageBoundConfirm || transaction.SessionID == nil ||
		*transaction.SessionID != principal.SessionID || transaction.UserID == nil ||
		*transaction.UserID != principal.User.ID || transaction.ExpiresAt.IsZero() {
		s.observe("failure")
		return Bound{}, ErrInvalid
	}
	s.observe("confirmable")
	return Bound{CSRFProof: proof, ExpiresAt: transaction.ExpiresAt, PostLogoutRedirectURI: transaction.PostLogoutRedirectURI}, nil
}

// Complete atomically confirms/cancels through the repository. A confirmed
// redirect is re-resolved after commit and is suppressed on any current-policy
// mismatch without undoing the local logout.
func (s *Service) Complete(ctx context.Context, lookup, csrfProof string, decision Decision, principal session.Principal, requestID string, now time.Time) (Completion, error) {
	lookupHash, lookupErr := DigestLookupToken(lookup)
	csrfHash, csrfErr := DigestCSRFProof(csrfProof)
	if lookupErr != nil || csrfErr != nil || (decision != DecisionConfirm && decision != DecisionCancel) ||
		!validPrincipal(principal) || now.IsZero() {
		s.observe("invalid")
		if csrfErr != nil {
			return Completion{}, ErrCSRF
		}
		return Completion{}, ErrNotFound
	}
	candidate, err := s.repository.CompleteLogoutTransaction(ctx, CompleteInput{
		LookupHash: lookupHash, CSRFHash: csrfHash, Decision: decision,
		UserID: principal.User.ID, SessionID: principal.SessionID,
		SessionBindingID: principal.SessionBindingID, Now: now.UTC(),
		RequestID: requestID, MaxAttempts: maxTransactionTries,
	})
	if err != nil {
		if errors.Is(err, ErrCSRF) || errors.Is(err, ErrNotFound) {
			s.observe("invalid")
		} else {
			s.observe("failure")
		}
		return Completion{}, err
	}
	result := Completion{Confirmed: candidate.Confirmed}
	if !candidate.Confirmed {
		s.observe("canceled")
		return result, nil
	}
	if candidate.VerifiedClientID != nil && candidate.PostLogoutRedirectURI != "" {
		clientValue, resolveErr := s.clients.GetActive(ctx, *candidate.VerifiedClientID)
		if resolveErr == nil && exactLogoutURI(clientValue, candidate.PostLogoutRedirectURI) &&
			(candidate.State == "" || !hasDecodedStateKey(candidate.PostLogoutRedirectURI)) {
			result.Location = appendState(candidate.PostLogoutRedirectURI, candidate.State)
		}
	}
	s.observe("confirmed")
	return result, nil
}

// DigestLookupToken validates and hashes a transient lookup cookie.
func DigestLookupToken(tokenValue string) ([]byte, error) {
	if !validSecret(tokenValue, lookupPrefix) {
		return nil, ErrInvalid
	}
	return hashLookup(tokenValue), nil
}

// DigestCSRFProof validates and hashes a transaction-bound hosted-form proof.
func DigestCSRFProof(tokenValue string) ([]byte, error) {
	if !validSecret(tokenValue, csrfPrefix) {
		return nil, ErrInvalid
	}
	return hashCSRF(tokenValue), nil
}

func hashLookup(tokenValue string) []byte {
	digest := sha256.Sum256([]byte("oneissuer:logout-transaction-lookup:v1:" + tokenValue))
	return digest[:]
}

func hashCSRF(tokenValue string) []byte {
	digest := sha256.Sum256([]byte("oneissuer:logout-confirm-csrf:v1:" + tokenValue))
	return digest[:]
}

func newSecret(source io.Reader, prefix string, digest func(string) []byte) (string, []byte, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", nil, errors.New("secure logout value generation failed")
	}
	tokenValue := prefix + base64.RawURLEncoding.EncodeToString(value)
	return tokenValue, digest(tokenValue), nil
}

func validSecret(tokenValue, prefix string) bool {
	if !strings.HasPrefix(tokenValue, prefix) || strings.TrimSpace(tokenValue) != tokenValue {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(tokenValue, prefix))
	return err == nil && len(decoded) == 32
}

func validStartInput(input StartInput) bool {
	if input.Now.IsZero() {
		return false
	}
	values := []string{input.IDTokenHint, input.ClientID, input.LogoutHint, input.PostLogoutRedirectURI, input.State, input.UILocales}
	for _, value := range values {
		if !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
			return false
		}
	}
	return len(input.IDTokenHint) <= maxCompactHintBytes && len(input.ClientID) <= maxPublicClientIDSize &&
		len(input.LogoutHint) <= maxStateBytes && len(input.PostLogoutRedirectURI) <= maxRedirectURIBytes &&
		len(input.State) <= maxStateBytes && len(input.UILocales) <= maxStateBytes
}

func validPrincipal(principal session.Principal) bool {
	return principal.SessionID != uuid.Nil && principal.SessionBindingID != uuid.Nil &&
		principal.User.ID != uuid.Nil && principal.User.Subject != ""
}

func (s *Service) verifyHint(compact string, now time.Time) (tokendomain.IDTokenClaims, bool) {
	if compact == "" || len(compact) > maxCompactHintBytes || strings.TrimSpace(compact) != compact || strings.Count(compact, ".") != 2 {
		return tokendomain.IDTokenClaims{}, false
	}
	parts := strings.Split(compact, ".")
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || !validHintHeader(headerBytes) {
		return tokendomain.IDTokenClaims{}, false
	}
	object, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(object.Signatures) != 1 {
		return tokendomain.IDTokenClaims{}, false
	}
	header := object.Signatures[0].Header
	typ, typeOK := header.ExtraHeaders[jose.HeaderKey("typ")].(string)
	if header.Algorithm != string(jose.RS256) || header.KeyID == "" || header.JSONWebKey != nil || header.Nonce != "" ||
		!typeOK || typ != "JWT" || len(header.ExtraHeaders) != 1 {
		return tokendomain.IDTokenClaims{}, false
	}
	var key *rsa.PublicKey
	for _, candidate := range s.keys.PublicKeys() {
		public, ok := candidate.Key.(*rsa.PublicKey)
		if candidate.KeyID == header.KeyID && candidate.Algorithm == string(jose.RS256) && candidate.Use == "sig" &&
			candidate.IsPublic() && ok && public != nil && public.N != nil && public.N.BitLen() >= 2048 {
			if key != nil {
				return tokendomain.IDTokenClaims{}, false
			}
			key = public
		}
	}
	if key == nil {
		return tokendomain.IDTokenClaims{}, false
	}
	payload, err := object.Verify(key)
	if err != nil || !uniqueJSONObject(payload) {
		return tokendomain.IDTokenClaims{}, false
	}
	var claims tokendomain.IDTokenClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return tokendomain.IDTokenClaims{}, false
	}
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	if claims.Issuer != s.issuer || claims.Audience == "" || claims.AuthorizedParty != claims.Audience ||
		claims.Subject == "" || len(claims.Subject) > maxHintSubjectBytes || strings.ContainsRune(claims.Subject, '\x00') ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || claims.AuthTime <= 0 ||
		expiresAt.Sub(issuedAt) > maxIDTokenLifetime || issuedAt.After(now.Add(s.clockSkew)) {
		return tokendomain.IDTokenClaims{}, false
	}
	if !now.After(expiresAt.Add(s.clockSkew)) || !now.After(issuedAt.Add(s.hintMaxAge).Add(s.clockSkew)) {
		return claims, true
	}
	return tokendomain.IDTokenClaims{}, false
}

// validHintHeader rejects duplicate members and requires the exact protected
// header vocabulary generated by OneIssuer. Checking the raw JSON before
// go-jose parsing avoids duplicate-member and recognized-but-unwanted JOSE
// header ambiguity (for example jku/x5c/crit).
func validHintHeader(payload []byte) bool {
	fields, ok := uniqueJSONObjectFields(payload)
	if !ok || len(fields) != 3 {
		return false
	}
	var algorithm, keyID, typ string
	if json.Unmarshal(fields["alg"], &algorithm) != nil || json.Unmarshal(fields["kid"], &keyID) != nil ||
		json.Unmarshal(fields["typ"], &typ) != nil {
		return false
	}
	return algorithm == string(jose.RS256) && keyID != "" && typ == "JWT"
}

func uniqueJSONObject(payload []byte) bool {
	_, ok := uniqueJSONObjectFields(payload)
	return ok
}

func uniqueJSONObjectFields(payload []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		member, err := decoder.Token()
		name, ok := member.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
		fields[name] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	return fields, true
}

func exactLogoutURI(clientValue clientdomain.Client, candidate string) bool {
	if candidate == "" || clientValue.ID == uuid.Nil || clientValue.Status != clientdomain.StatusActive {
		return false
	}
	for _, registered := range clientValue.LogoutURIs {
		if registered == candidate {
			return true
		}
	}
	return false
}

func hasDecodedStateKey(rawURI string) bool {
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Fragment != "" {
		return true
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return true
	}
	_, exists := values["state"]
	return exists
}

func appendState(rawURI, state string) string {
	if state == "" {
		return rawURI
	}
	separator := "?"
	if strings.Contains(rawURI, "?") {
		separator = "&"
	}
	return rawURI + separator + "state=" + url.QueryEscape(state)
}

func (s *Service) observe(result string) {
	if s.metrics != nil {
		s.metrics.RPLogout(result)
	}
}
