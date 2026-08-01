// Package client owns the phase-two OIDC Client registry, exact URI rules,
// bounded scope selection, and one-time confidential secret lifecycle. It does
// not implement OIDC protocol endpoints.
package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/pagination"
)

// Type distinguishes public clients from confidential clients.
type Type string

// AuthMethod is the token-endpoint authentication method recorded for a client.
type AuthMethod string

// Status controls whether a client may be used.
type Status string

// Supported client types, authentication methods, and statuses.
const (
	TypePublic       Type = "public"
	TypeConfidential Type = "confidential"

	AuthMethodNone              AuthMethod = "none"
	AuthMethodClientSecretBasic AuthMethod = "client_secret_basic"

	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

var (
	// ErrInvalid identifies a client policy or syntax failure.
	ErrInvalid = errors.New("client input is invalid")
	// ErrNotFound hides unknown and invalid client credentials.
	ErrNotFound = errors.New("client not found")
	// ErrConflict identifies duplicate or optimistic-concurrency conflicts.
	ErrConflict = errors.New("client conflict")
	// ErrPublicSecret rejects secret operations for public clients.
	ErrPublicSecret = errors.New("public clients cannot have secrets")
)

// ValidationError contains only a stable field/code pair, never submitted data.
type ValidationError struct {
	Field string
	Code  string
}

func (e *ValidationError) Error() string { return ErrInvalid.Error() }
func (e *ValidationError) Unwrap() error { return ErrInvalid }

// Client never includes a secret digest or clear secret.
type Client struct {
	ID                      uuid.UUID  `json:"id"`
	ClientID                string     `json:"client_id"`
	Type                    Type       `json:"client_type"`
	TokenEndpointAuthMethod AuthMethod `json:"token_endpoint_auth_method"`
	Name                    string     `json:"name"`
	Description             string     `json:"description"`
	LogoURI                 string     `json:"logo_uri,omitempty"`
	Status                  Status     `json:"status"`
	RegistrationEnabled     bool       `json:"registration_enabled"`
	RedirectURIs            []string   `json:"redirect_uris"`
	LogoutURIs              []string   `json:"logout_uris"`
	Scopes                  []string   `json:"scopes"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
	Version                 time.Time  `json:"-"`
}

// SecretRecord is the database-safe representation of a confidential secret.
type SecretRecord struct {
	ID         uuid.UUID
	ClientID   uuid.UUID
	SecretHash []byte
	CreatedAt  time.Time
}

// Created is the only response model allowed to carry a one-time secret.
type Created struct {
	Client Client `json:"client"`
	Secret string `json:"client_secret,omitempty"`
}

// CreateInput contains fields accepted when registering a client.
type CreateInput struct {
	Type                Type
	Name                string
	Description         string
	LogoURI             string
	RegistrationEnabled bool
	RedirectURIs        []string
	LogoutURIs          []string
	Scopes              []string
}

// UpdateInput is the restricted administrative client patch model.
type UpdateInput struct {
	Name                *string
	Description         *string
	LogoURI             *string
	Status              *Status
	RegistrationEnabled *bool
	RedirectURIs        *[]string
	LogoutURIs          *[]string
	Scopes              *[]string
}

// Repository is the atomic persistence boundary for the client registry.
type Repository interface {
	CreateClient(context.Context, Client, *SecretRecord, audit.Event) error
	GetClient(context.Context, uuid.UUID) (Client, error)
	GetClientByPublicID(context.Context, string) (Client, error)
	ListClients(context.Context, pagination.Cursor, int) ([]Client, error)
	UpdateClient(context.Context, Client, audit.Event) error
	RotateClientSecret(context.Context, uuid.UUID, SecretRecord, time.Time, audit.Event) error
	GetClientSecretHashes(context.Context, string) (Client, [][]byte, error)
}

// Metrics records low-cardinality client operation outcomes.
type Metrics interface {
	ClientOperation(operation, result string)
}

// Service enforces client metadata, URI, scope, and secret policy.
type Service struct {
	repository          Repository
	random              io.Reader
	allowHTTPOnLoopback bool
	allowedScopes       map[string]bool
	metrics             Metrics
}

// NewService creates a client registry service.
func NewService(repository Repository, randomSource io.Reader, allowHTTPOnLoopback bool, metrics Metrics) *Service {
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &Service{
		repository: repository, random: randomSource, allowHTTPOnLoopback: allowHTTPOnLoopback,
		allowedScopes: map[string]bool{"openid": true, "profile": true, "email": true, "offline_access": true},
		metrics:       metrics,
	}
}

// Create registers a client and returns a confidential clear secret once.
func (s *Service) Create(ctx context.Context, actor uuid.UUID, input CreateInput, requestID string, now time.Time) (Created, error) {
	clientValue, secretRecord, clearSecret, err := s.prepareCreate(input, now)
	if err != nil {
		s.observe("create", "rejected")
		return Created{}, err
	}
	event, err := audit.New(audit.ClientCreated, audit.ResultSuccess, &actor, audit.TargetClient, &clientValue.ID, requestID,
		[]string{"created", "redirect_uris", "logout_uris", "scopes"}, now)
	if err != nil {
		return Created{}, err
	}
	if err := s.repository.CreateClient(ctx, clientValue, secretRecord, event); err != nil {
		s.observe("create", "failure")
		return Created{}, err
	}
	s.observe("create", "success")
	return Created{Client: clientValue, Secret: clearSecret}, nil
}

// Get returns a credential-free client representation.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Client, error) {
	return s.repository.GetClient(ctx, id)
}

// GetActive returns one active, internally consistent Client by its immutable
// database identifier. Protocol continuation paths use this after restoring a
// server-side authorization transaction; browser input never selects this ID.
func (s *Service) GetActive(ctx context.Context, id uuid.UUID) (Client, error) {
	if id == uuid.Nil {
		return Client{}, ErrNotFound
	}
	value, err := s.repository.GetClient(ctx, id)
	if err != nil || !activeClientRecord(value) {
		return Client{}, ErrNotFound
	}
	return value, nil
}

// ResolveActive returns an active credential-free Client by its public
// client_id. Unknown, malformed, disabled, and internally inconsistent records
// deliberately share ErrNotFound so protocol callers cannot enumerate policy.
func (s *Service) ResolveActive(ctx context.Context, publicID string) (Client, error) {
	if !validClientID(publicID) {
		return Client{}, ErrNotFound
	}
	value, err := s.repository.GetClientByPublicID(ctx, publicID)
	if err != nil || !activeClientRecord(value) {
		return Client{}, ErrNotFound
	}
	return value, nil
}

// List returns a bounded page of credential-free clients.
func (s *Service) List(ctx context.Context, cursor pagination.Cursor, limit int) ([]Client, error) {
	return s.repository.ListClients(ctx, cursor, pagination.Limit(limit)+1)
}

// Update validates and atomically persists an administrative client patch.
func (s *Service) Update(ctx context.Context, actor uuid.UUID, id uuid.UUID, input UpdateInput, requestID string, now time.Time) (Client, []string, error) {
	existing, err := s.repository.GetClient(ctx, id)
	if err != nil {
		return Client{}, nil, err
	}
	updated, changed, err := s.prepareUpdate(existing, input, now)
	if err != nil {
		s.observe("update", "rejected")
		return Client{}, nil, err
	}
	eventType := audit.ClientUpdated
	if existing.Status != StatusDisabled && updated.Status == StatusDisabled {
		eventType = audit.ClientDisabled
	}
	event, err := audit.New(eventType, audit.ResultSuccess, &actor, audit.TargetClient, &id, requestID, changed, now)
	if err != nil {
		return Client{}, nil, err
	}
	if err := s.repository.UpdateClient(ctx, updated, event); err != nil {
		s.observe("update", "failure")
		return Client{}, nil, err
	}
	s.observe("update", "success")
	return updated, changed, nil
}

// RotateSecret atomically invalidates old secrets and returns the replacement once.
func (s *Service) RotateSecret(ctx context.Context, actor, id uuid.UUID, requestID string, now time.Time) (string, error) {
	existing, err := s.repository.GetClient(ctx, id)
	if err != nil {
		return "", err
	}
	if existing.Type != TypeConfidential {
		s.observe("rotate_secret", "rejected")
		return "", ErrPublicSecret
	}
	clearSecret, record, err := s.newSecret(id, now)
	if err != nil {
		return "", err
	}
	event, err := audit.New(audit.ClientSecretRotated, audit.ResultSuccess, &actor, audit.TargetClient, &id, requestID, []string{"secret"}, now)
	if err != nil {
		return "", err
	}
	if err := s.repository.RotateClientSecret(ctx, id, *record, now.UTC(), event); err != nil {
		s.observe("rotate_secret", "failure")
		return "", err
	}
	s.observe("rotate_secret", "success")
	return clearSecret, nil
}

// ValidateSecret compares a presented confidential secret in constant time.
func (s *Service) ValidateSecret(ctx context.Context, clientID, clearSecret string) (Client, error) {
	if !validSecret(clearSecret) {
		return Client{}, ErrNotFound
	}
	clientValue, hashes, err := s.repository.GetClientSecretHashes(ctx, clientID)
	if err != nil || clientValue.Status != StatusActive || clientValue.Type != TypeConfidential {
		return Client{}, ErrNotFound
	}
	presented := HashSecret(clearSecret)
	matched := 0
	for _, expected := range hashes {
		if len(expected) == sha256.Size {
			matched |= subtle.ConstantTimeCompare(presented, expected)
		}
	}
	if matched != 1 {
		return Client{}, ErrNotFound
	}
	return clientValue, nil
}

// RedirectURIMatches is deliberately byte-for-byte after structural validation.
func (s *Service) RedirectURIMatches(clientValue Client, candidate string) bool {
	if validateURI(candidate, s.allowHTTPOnLoopback) != nil {
		return false
	}
	for _, registered := range clientValue.RedirectURIs {
		if registered == candidate {
			return true
		}
	}
	return false
}

func (s *Service) prepareCreate(input CreateInput, now time.Time) (Client, *SecretRecord, string, error) {
	if input.Type != TypePublic && input.Type != TypeConfidential {
		return Client{}, nil, "", &ValidationError{Field: "client_type", Code: "invalid_value"}
	}
	name, description, logo, redirects, logouts, scopes, err := s.validateProfile(input.Name, input.Description, input.LogoURI, input.RedirectURIs, input.LogoutURIs, input.Scopes)
	if err != nil {
		return Client{}, nil, "", err
	}
	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return Client{}, nil, "", errors.New("client identifier generation failed")
	}
	publicID, err := randomValue(s.random, "ois_cli_", 24)
	if err != nil {
		return Client{}, nil, "", err
	}
	authMethod := AuthMethodNone
	if input.Type == TypeConfidential {
		authMethod = AuthMethodClientSecretBasic
	}
	now = now.UTC()
	value := Client{
		ID: id, ClientID: publicID, Type: input.Type, TokenEndpointAuthMethod: authMethod,
		Name: name, Description: description, LogoURI: logo, Status: StatusActive,
		RegistrationEnabled: input.RegistrationEnabled, RedirectURIs: redirects,
		LogoutURIs: logouts, Scopes: scopes, CreatedAt: now, UpdatedAt: now,
		Version: now,
	}
	if input.Type == TypePublic {
		return value, nil, "", nil
	}
	clearSecret, record, err := s.newSecret(id, now)
	return value, record, clearSecret, err
}

func (s *Service) prepareUpdate(existing Client, input UpdateInput, now time.Time) (Client, []string, error) {
	updated := existing
	changed := make([]string, 0, 8)
	if input.Name != nil && *input.Name != existing.Name {
		updated.Name = *input.Name
		changed = append(changed, "name")
	}
	if input.Description != nil && *input.Description != existing.Description {
		updated.Description = *input.Description
		changed = append(changed, "description")
	}
	if input.LogoURI != nil && *input.LogoURI != existing.LogoURI {
		updated.LogoURI = *input.LogoURI
		changed = append(changed, "logo_uri")
	}
	if input.Status != nil {
		if *input.Status != StatusActive && *input.Status != StatusDisabled {
			return Client{}, nil, &ValidationError{Field: "status", Code: "invalid_value"}
		}
		if *input.Status != existing.Status {
			updated.Status = *input.Status
			changed = append(changed, "status")
		}
	}
	if input.RegistrationEnabled != nil && *input.RegistrationEnabled != existing.RegistrationEnabled {
		updated.RegistrationEnabled = *input.RegistrationEnabled
		changed = append(changed, "registration_enabled")
	}
	if input.RedirectURIs != nil {
		updated.RedirectURIs = *input.RedirectURIs
		changed = append(changed, "redirect_uris")
	}
	if input.LogoutURIs != nil {
		updated.LogoutURIs = *input.LogoutURIs
		changed = append(changed, "logout_uris")
	}
	if input.Scopes != nil {
		updated.Scopes = *input.Scopes
		changed = append(changed, "scopes")
	}
	name, description, logo, redirects, logouts, scopes, err := s.validateProfile(updated.Name, updated.Description, updated.LogoURI, updated.RedirectURIs, updated.LogoutURIs, updated.Scopes)
	if err != nil {
		return Client{}, nil, err
	}
	updated.Name, updated.Description, updated.LogoURI = name, description, logo
	updated.RedirectURIs, updated.LogoutURIs, updated.Scopes = redirects, logouts, scopes
	if len(changed) == 0 {
		return Client{}, nil, &ValidationError{Field: "body", Code: "no_changes"}
	}
	updated.UpdatedAt = now.UTC()
	return updated, changed, nil
}

func (s *Service) validateProfile(name, description, logo string, redirects, logouts, scopes []string) (string, string, string, []string, []string, []string, error) {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	logo = strings.TrimSpace(logo)
	if !utf8.ValidString(name) || len([]rune(name)) < 1 || len([]rune(name)) > 128 {
		return "", "", "", nil, nil, nil, &ValidationError{Field: "name", Code: "invalid_length"}
	}
	if !utf8.ValidString(description) || len(description) > 2048 {
		return "", "", "", nil, nil, nil, &ValidationError{Field: "description", Code: "invalid_length"}
	}
	if logo != "" && validateURI(logo, s.allowHTTPOnLoopback) != nil {
		return "", "", "", nil, nil, nil, &ValidationError{Field: "logo_uri", Code: "invalid_uri"}
	}
	redirects, err := validateURIs("redirect_uris", redirects, s.allowHTTPOnLoopback, true)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	logouts, err = validateURIs("logout_uris", logouts, s.allowHTTPOnLoopback, false)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	scopes, err = s.validateScopes(scopes)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	return name, description, logo, redirects, logouts, scopes, nil
}

func (s *Service) validateScopes(scopes []string) ([]string, error) {
	values := canonical(scopes)
	if len(values) == 0 || len(values) > len(s.allowedScopes) {
		return nil, &ValidationError{Field: "scopes", Code: "invalid_count"}
	}
	for _, scope := range values {
		if !s.allowedScopes[scope] {
			return nil, &ValidationError{Field: "scopes", Code: "unsupported_scope"}
		}
	}
	if !s.allowedScopes["openid"] || !contains(values, "openid") {
		return nil, &ValidationError{Field: "scopes", Code: "openid_required"}
	}
	return values, nil
}

func validateURIs(field string, values []string, allowLoopback, required bool) ([]string, error) {
	values = canonical(values)
	if (required && len(values) == 0) || len(values) > 32 {
		return nil, &ValidationError{Field: field, Code: "invalid_count"}
	}
	for _, value := range values {
		if validateURI(value, allowLoopback) != nil {
			return nil, &ValidationError{Field: field, Code: "invalid_uri"}
		}
	}
	return values, nil
}

func validateURI(raw string, allowLoopback bool) error {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.Contains(raw, "*") || strings.ContainsAny(raw, "\r\n\t") {
		return ErrInvalid
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return ErrInvalid
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" || !allowLoopback {
		return ErrInvalid
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ErrInvalid
	}
	return nil
}

func (s *Service) newSecret(clientID uuid.UUID, now time.Time) (string, *SecretRecord, error) {
	clearSecret, err := randomValue(s.random, "ois_sec_v1_", 32)
	if err != nil {
		return "", nil, err
	}
	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return "", nil, errors.New("secret identifier generation failed")
	}
	return clearSecret, &SecretRecord{ID: id, ClientID: clientID, SecretHash: HashSecret(clearSecret), CreatedAt: now.UTC()}, nil
}

func randomValue(source io.Reader, prefix string, size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", errors.New("secure client value generation failed")
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value), nil
}

// HashSecret returns the domain-separated lookup digest stored in PostgreSQL.
func HashSecret(clearSecret string) []byte {
	sum := sha256.Sum256([]byte("oneissuer:client-secret:v1:" + clearSecret))
	return sum[:]
}

func validSecret(clearSecret string) bool {
	if !strings.HasPrefix(clearSecret, "ois_sec_v1_") {
		return false
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(clearSecret, "ois_sec_v1_"))
	return err == nil && len(value) == 32
}

func validClientID(value string) bool {
	if !strings.HasPrefix(value, "ois_cli_") || strings.TrimSpace(value) != value {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, "ois_cli_"))
	return err == nil && len(decoded) == 24
}

func activeClientRecord(value Client) bool {
	return value.ID != uuid.Nil && value.Status == StatusActive &&
		((value.Type == TypePublic && value.TokenEndpointAuthMethod == AuthMethodNone) ||
			(value.Type == TypeConfidential && value.TokenEndpointAuthMethod == AuthMethodClientSecretBasic))
}

func canonical(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	output := result[:0]
	for _, value := range result {
		if len(output) == 0 || output[len(output)-1] != value {
			output = append(output, value)
		}
	}
	return output
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func (s *Service) observe(operation, result string) {
	if s.metrics != nil {
		s.metrics.ClientOperation(operation, result)
	}
}
