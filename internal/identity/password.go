package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Version  = 19
	defaultSaltLen = 16
	defaultKeyLen  = 32
)

var (
	// ErrHashBusy indicates that the bounded Argon2 worker budget is exhausted.
	ErrHashBusy = errors.New("password hashing capacity is busy")
	// ErrInvalidHash identifies malformed/out-of-policy PHC data without
	// including the digest in an error string.
	ErrInvalidHash = errors.New("password hash is invalid")
)

// PasswordPolicy is independent from Argon2 resource parameters.
type PasswordPolicy struct {
	MinLength int
	MaxBytes  int
}

// ValidatePassword validates the exact submitted bytes. It deliberately does
// not trim, normalize, or change case.
func (p PasswordPolicy) ValidatePassword(password string) error {
	if !utf8.ValidString(password) || strings.IndexByte(password, 0) >= 0 {
		return &ValidationError{Field: "password", Code: "invalid_encoding"}
	}
	if len(password) > p.MaxBytes {
		return &ValidationError{Field: "password", Code: "too_large"}
	}
	if utf8.RuneCountInString(password) < p.MinLength {
		return &ValidationError{Field: "password", Code: "too_short"}
	}
	return nil
}

// Argon2Params is the PHC parameter set used for newly-created credentials.
type Argon2Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	SaltLen   uint32
	KeyLen    uint32
}

// PasswordHasher provides bounded Argon2id hashing and verification.
type PasswordHasher struct {
	params Argon2Params
	random io.Reader
	gate   chan struct{}
}

// NewPasswordHasher creates a hasher. Deployment-safe parameter lower/upper
// bounds are enforced by config; this constructor still rejects zero values so
// library callers cannot panic Argon2.
func NewPasswordHasher(params Argon2Params, maximumConcurrent int, randomSource io.Reader) (*PasswordHasher, error) {
	if params.MemoryKiB == 0 || params.Time == 0 || params.Threads == 0 {
		return nil, ErrInvalidHash
	}
	if params.SaltLen == 0 {
		params.SaltLen = defaultSaltLen
	}
	if params.KeyLen == 0 {
		params.KeyLen = defaultKeyLen
	}
	if params.SaltLen < 16 || params.SaltLen > 64 || params.KeyLen < 16 || params.KeyLen > 64 || maximumConcurrent < 1 {
		return nil, ErrInvalidHash
	}
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &PasswordHasher{params: params, random: randomSource, gate: make(chan struct{}, maximumConcurrent)}, nil
}

// Hash produces a standard Argon2id PHC string.
func (h *PasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	salt := make([]byte, h.params.SaltLen)
	if _, err := io.ReadFull(h.random, salt); err != nil {
		return "", fmt.Errorf("password salt generation failed")
	}
	digest := argon2.IDKey([]byte(password), salt, h.params.Time, h.params.MemoryKiB, h.params.Threads, h.params.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version, h.params.MemoryKiB, h.params.Time, h.params.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest)), nil
}

// Verify checks a PHC digest in constant time and reports whether a successful
// credential should be rehashed with current parameters.
func (h *PasswordHasher) Verify(ctx context.Context, password, encoded string) (matches, needsRehash bool, err error) {
	params, salt, expected, err := parsePHC(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	// #nosec G115 -- parsePHC restricts digest lengths to 16..64 bytes.
	expectedLength := uint32(len(expected))
	actual := argon2.IDKey([]byte(password), salt, params.Time, params.MemoryKiB, params.Threads, expectedLength)
	matches = subtle.ConstantTimeCompare(actual, expected) == 1
	// #nosec G115 -- parsePHC restricts salt lengths to 16..64 bytes.
	saltLength := uint32(len(salt))
	needsRehash = matches && (params.MemoryKiB != h.params.MemoryKiB || params.Time != h.params.Time ||
		params.Threads != h.params.Threads || saltLength != h.params.SaltLen || expectedLength != h.params.KeyLen)
	return matches, needsRehash, nil
}

func (h *PasswordHasher) acquire(ctx context.Context) error {
	select {
	case h.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return ErrHashBusy
	}
}

func (h *PasswordHasher) release() { <-h.gate }

func parsePHC(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	values := make(map[string]uint64, 3)
	for _, item := range parameterParts {
		pair := strings.SplitN(item, "=", 2)
		if len(pair) != 2 || values[pair[0]] != 0 {
			return Argon2Params{}, nil, nil, ErrInvalidHash
		}
		value, parseErr := strconv.ParseUint(pair[1], 10, 32)
		if parseErr != nil || value == 0 {
			return Argon2Params{}, nil, nil, ErrInvalidHash
		}
		values[pair[0]] = value
	}
	if values["m"] < 8*1024 || values["m"] > 1024*1024 || values["t"] > 20 || values["p"] > 32 {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	salt, saltErr := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	digest, digestErr := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if saltErr != nil || digestErr != nil || len(salt) < 16 || len(salt) > 64 || len(digest) < 16 || len(digest) > 64 {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	// #nosec G115 -- every PHC numeric and decoded-length value is explicitly bounded above.
	return Argon2Params{MemoryKiB: uint32(values["m"]), Time: uint32(values["t"]), Threads: uint8(values["p"]), SaltLen: uint32(len(salt)), KeyLen: uint32(len(digest))}, salt, digest, nil
}
