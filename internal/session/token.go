package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

const tokenBytes = 32

// TokenManager generates domain-separated, versioned opaque values and their
// irreversible SHA-256 lookup digests.
type TokenManager struct {
	random      io.Reader
	sessionTTL  time.Duration
	idleTimeout time.Duration
	csrfTTL     time.Duration
}

// NewTokenManager creates a generator with bounded absolute, idle, and CSRF lifetimes.
func NewTokenManager(randomSource io.Reader, sessionTTL, idleTimeout, csrfTTL time.Duration) (*TokenManager, error) {
	if randomSource == nil {
		randomSource = rand.Reader
	}
	if sessionTTL <= 0 || idleTimeout <= 0 || idleTimeout > sessionTTL || csrfTTL <= 0 {
		return nil, errors.New("invalid session lifetime configuration")
	}
	return &TokenManager{random: randomSource, sessionTTL: sessionTTL, idleTimeout: idleTimeout, csrfTTL: csrfTTL}, nil
}

// NewAuthenticated creates clear browser values and their database-safe record.
func (m *TokenManager) NewAuthenticated(userID uuid.UUID, now time.Time, userAgent string, clientIP netip.Addr) (Issued, error) {
	token, err := m.newToken("s1_")
	if err != nil {
		return Issued{}, err
	}
	csrf, err := m.newToken("c1_")
	if err != nil {
		return Issued{}, err
	}
	id, err := uuid.NewRandomFromReader(m.random)
	if err != nil {
		return Issued{}, errors.New("session identifier generation failed")
	}
	now = now.UTC()
	expires := now.Add(m.sessionTTL)
	idleExpires := now.Add(m.idleTimeout)
	if idleExpires.After(expires) {
		idleExpires = expires
	}
	return Issued{
		Token: token, CSRFToken: csrf,
		Record: Record{
			ID: id, UserID: userID, SessionBindingID: id, TokenHash: HashToken(token), CSRFHash: HashCSRF(csrf),
			CSRFExpiresAt: now.Add(m.csrfTTL), CreatedAt: now, LastSeenAt: now,
			AuthenticatedAt: now, ExpiresAt: expires, IdleExpiresAt: idleExpires,
			UserAgentHash: hashOptional("oneissuer:user-agent:v1:", userAgent),
			IPPrefix:      coarseIP(clientIP),
		},
	}, nil
}

// NewPreAuth creates a CSRF-bound pre-authentication session.
func (m *TokenManager) NewPreAuth(transactionID uuid.UUID, now time.Time) (IssuedPreAuth, error) {
	token, err := m.newToken("p1_")
	if err != nil {
		return IssuedPreAuth{}, err
	}
	csrf, err := m.newToken("c1_")
	if err != nil {
		return IssuedPreAuth{}, err
	}
	id, err := uuid.NewRandomFromReader(m.random)
	if err != nil {
		return IssuedPreAuth{}, errors.New("pre-auth identifier generation failed")
	}
	now = now.UTC()
	return IssuedPreAuth{
		Token: token, CSRFToken: csrf,
		Record: PreAuthRecord{
			ID: id, TokenHash: HashToken(token), CSRFHash: HashCSRF(csrf),
			AuthTransactionID: transactionID, CreatedAt: now, ExpiresAt: now.Add(m.csrfTTL),
		},
	}, nil
}

// NewCSRF creates a clear token, its digest, and authoritative expiry.
func (m *TokenManager) NewCSRF(now time.Time) (token string, hash []byte, expires time.Time, err error) {
	token, err = m.newToken("c1_")
	if err != nil {
		return "", nil, time.Time{}, err
	}
	return token, HashCSRF(token), now.UTC().Add(m.csrfTTL), nil
}

// ValidatePreAuth checks the opaque pre-auth cookie and its bound form token
// without revealing which component failed.
func (m *TokenManager) ValidatePreAuth(record PreAuthRecord, clearCookie, clearCSRF string, now time.Time) error {
	if !validToken(clearCookie, "p1_") || record.ConsumedAt != nil || !now.UTC().Before(record.ExpiresAt) {
		return ErrUnauthenticated
	}
	if subtle.ConstantTimeCompare(HashToken(clearCookie), record.TokenHash) != 1 || !csrfMatches(clearCSRF, record.CSRFHash) {
		return ErrInvalidCSRF
	}
	return nil
}

// NextIdleExpiry advances idle expiry without exceeding absolute expiry.
func (m *TokenManager) NextIdleExpiry(now, absolute time.Time) time.Time {
	next := now.UTC().Add(m.idleTimeout)
	if next.After(absolute) {
		return absolute
	}
	return next
}

func (m *TokenManager) newToken(prefix string) (string, error) {
	value := make([]byte, tokenBytes)
	if _, err := io.ReadFull(m.random, value); err != nil {
		return "", errors.New("secure token generation failed")
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func validToken(value string, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == tokenBytes
}

// HashToken is safe to persist; the clear token remains browser-only.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte("oneissuer:browser-token:v1:" + token))
	return sum[:]
}

// HashCSRF is domain-separated from session lookup hashes.
func HashCSRF(token string) []byte {
	sum := sha256.Sum256([]byte("oneissuer:csrf:v1:" + token))
	return sum[:]
}

func csrfMatches(token string, expected []byte) bool {
	if !validToken(token, "c1_") || len(expected) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(HashCSRF(token), expected) == 1
}

func hashOptional(prefix, value string) []byte {
	if value == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(prefix + value))
	return sum[:]
}

func coarseIP(address netip.Addr) string {
	if !address.IsValid() {
		return ""
	}
	address = address.Unmap()
	bits := 56
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}
