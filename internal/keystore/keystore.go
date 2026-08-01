// Package keystore loads, validates, signs with, and publishes the phase-three
// RS256 key ring. Private key material never leaves this package.
package keystore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// Algorithm is the only signing algorithm supported by the initial profile.
	Algorithm = string(jose.RS256)
	// DefaultRSABits is used by the key generation CLI.
	DefaultRSABits = 3072
	minRSABits     = 2048
	maxKeyFileSize = 1 << 20
)

var (
	// ErrInvalid identifies a key file or key-ring policy violation without
	// exposing private material in the error.
	ErrInvalid = errors.New("signing key material is invalid")
	// ErrExists prevents accidental replacement of key material.
	ErrExists = errors.New("key output already exists")
)

// Store is an immutable active signer plus the public verification ring.
type Store struct {
	activePrivate jose.JSONWebKey
	publicKeys    []jose.JSONWebKey
	jwks          []byte
	etag          string
}

// Metadata is safe for CLI/config diagnostics.
type Metadata struct {
	ActiveKeyID   string
	PublishedKeys int
}

// Load validates one active private JWK and an optional public JWKS file.
func Load(activePrivateFile, verificationKeysFile string) (*Store, error) {
	active, err := loadPrivate(activePrivateFile)
	if err != nil {
		return nil, err
	}

	publicKeys := []jose.JSONWebKey{active.Public()}
	seen := map[string]struct{}{active.KeyID: {}}
	if verificationKeysFile != "" {
		additional, loadErr := loadPublicSet(verificationKeysFile)
		if loadErr != nil {
			return nil, loadErr
		}
		for _, key := range additional {
			if _, duplicate := seen[key.KeyID]; duplicate {
				return nil, fmt.Errorf("%w: duplicate public key identifier", ErrInvalid)
			}
			seen[key.KeyID] = struct{}{}
			publicKeys = append(publicKeys, key)
		}
	}

	sort.Slice(publicKeys, func(i, j int) bool { return publicKeys[i].KeyID < publicKeys[j].KeyID })
	jwks, err := marshalPublicSet(publicKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: public key serialization failed", ErrInvalid)
	}
	digest := sha256.Sum256(jwks)
	return &Store{
		activePrivate: active,
		publicKeys:    publicKeys,
		jwks:          jwks,
		etag:          `"` + hex.EncodeToString(digest[:]) + `"`,
	}, nil
}

// Metadata returns only public operational facts.
func (s *Store) Metadata() Metadata {
	if s == nil {
		return Metadata{}
	}
	return Metadata{ActiveKeyID: s.activePrivate.KeyID, PublishedKeys: len(s.publicKeys)}
}

// PublicJWKS returns a defensive copy of the deterministic public JWK Set JSON.
func (s *Store) PublicJWKS() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.jwks...)
}

// ETag returns a strong ETag derived only from public JWKS content.
func (s *Store) ETag() string {
	if s == nil {
		return ""
	}
	return s.etag
}

// PublicKeys returns a defensive copy for strict local JWT verification.
func (s *Store) PublicKeys() []jose.JSONWebKey {
	if s == nil {
		return nil
	}
	return append([]jose.JSONWebKey(nil), s.publicKeys...)
}

// Sign signs payload as compact JWS with fixed RS256, active kid, and caller-
// selected allowlisted typ. Callers construct and marshal claims separately.
func (s *Store) Sign(payload []byte, typ string) (string, error) {
	if s == nil || (typ != "JWT" && typ != "at+jwt") {
		return "", ErrInvalid
	}
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.activePrivate}, options)
	if err != nil {
		return "", errors.New("token signer initialization failed")
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", errors.New("token signing failed")
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		return "", errors.New("token serialization failed")
	}
	return compact, nil
}

// Generate creates a new private RSA JWK exclusively with mode 0600. It never
// replaces an existing path and never returns private material.
func Generate(path string, bits int, random io.Reader) (Metadata, error) {
	if strings.TrimSpace(path) == "" || bits < minRSABits {
		return Metadata{}, ErrInvalid
	}
	if random == nil {
		random = rand.Reader
	}
	key, err := rsa.GenerateKey(random, bits)
	if err != nil {
		return Metadata{}, errors.New("RSA key generation failed")
	}
	if err := key.Validate(); err != nil {
		return Metadata{}, errors.New("generated RSA key validation failed")
	}
	jwk, err := newPrivateJWK(key)
	if err != nil {
		return Metadata{}, err
	}
	encoded, err := marshalIndented(jwk)
	if err != nil {
		return Metadata{}, errors.New("private JWK serialization failed")
	}
	if err := writeExclusive(path, encoded, 0o600); err != nil {
		return Metadata{}, err
	}
	return Metadata{ActiveKeyID: jwk.KeyID, PublishedKeys: 1}, nil
}

// WritePublic reads a valid private JWK and exclusively writes its public JWKS.
func WritePublic(privatePath, outputPath string) (Metadata, error) {
	private, err := loadPrivate(privatePath)
	if err != nil {
		return Metadata{}, err
	}
	encoded, err := marshalPublicSet([]jose.JSONWebKey{private.Public()})
	if err != nil {
		return Metadata{}, errors.New("public JWKS serialization failed")
	}
	if err := writeExclusive(outputPath, encoded, 0o644); err != nil {
		return Metadata{}, err
	}
	return Metadata{ActiveKeyID: private.KeyID, PublishedKeys: 1}, nil
}

func loadPrivate(path string) (jose.JSONWebKey, error) {
	data, info, err := readRegularFile(path, true)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return jose.JSONWebKey{}, fmt.Errorf("%w: private key file permissions are too broad", ErrInvalid)
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(data, &key); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("%w: private JWK could not be decoded", ErrInvalid)
	}
	private, ok := key.Key.(*rsa.PrivateKey)
	if !ok || private == nil || private.N == nil || private.N.BitLen() < minRSABits || private.Validate() != nil {
		return jose.JSONWebKey{}, fmt.Errorf("%w: active key must be a valid RSA private key", ErrInvalid)
	}
	if err := validateMetadata(&key); err != nil {
		return jose.JSONWebKey{}, err
	}
	return key, nil
}

func loadPublicSet(path string) ([]jose.JSONWebKey, error) {
	data, _, err := readRegularFile(path, false)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) == 0 {
		return nil, fmt.Errorf("%w: verification JWKS could not be decoded", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(set.Keys))
	for index := range set.Keys {
		key := &set.Keys[index]
		public, ok := key.Key.(*rsa.PublicKey)
		if !key.IsPublic() || !ok || public == nil || public.N == nil || public.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("%w: verification set must contain RSA public keys only", ErrInvalid)
		}
		if err := validateMetadata(key); err != nil {
			return nil, err
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate verification key identifier", ErrInvalid)
		}
		seen[key.KeyID] = struct{}{}
	}
	return set.Keys, nil
}

func validateMetadata(key *jose.JSONWebKey) error {
	if key.Algorithm != Algorithm || key.Use != "sig" {
		return fmt.Errorf("%w: key algorithm/use must be RS256/sig", ErrInvalid)
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: key thumbprint failed", ErrInvalid)
	}
	want := base64.RawURLEncoding.EncodeToString(thumbprint)
	if key.KeyID == "" || key.KeyID != want {
		return fmt.Errorf("%w: key identifier does not match RFC 7638 thumbprint", ErrInvalid)
	}
	if len(key.Certificates) != 0 || key.CertificatesURL != nil || len(key.CertificateThumbprintSHA1) != 0 || len(key.CertificateThumbprintSHA256) != 0 {
		return fmt.Errorf("%w: X.509 key metadata is not supported", ErrInvalid)
	}
	return nil
}

func newPrivateJWK(key *rsa.PrivateKey) (jose.JSONWebKey, error) {
	jwk := jose.JSONWebKey{Key: key, Algorithm: Algorithm, Use: "sig"}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return jose.JSONWebKey{}, errors.New("generated key thumbprint failed")
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)
	return jwk, nil
}

func readRegularFile(path string, rejectBroadPermissions bool) ([]byte, os.FileInfo, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, fmt.Errorf("%w: key path is empty", ErrInvalid)
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: key file cannot be inspected", ErrInvalid)
	}
	if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: key path must be a regular non-symlink file", ErrInvalid)
	}
	// #nosec G304 -- this package exists to open the explicitly configured key
	// path after lstat/type/symlink checks and verifies identity again below.
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: key file cannot be opened", ErrInvalid)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(lstat, info) {
		return nil, nil, fmt.Errorf("%w: key file changed while opening", ErrInvalid)
	}
	if rejectBroadPermissions && info.Mode().Perm()&0o077 != 0 {
		return nil, nil, fmt.Errorf("%w: private key file permissions are too broad", ErrInvalid)
	}
	limited := io.LimitReader(file, maxKeyFileSize+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) == 0 || len(data) > maxKeyFileSize {
		return nil, nil, fmt.Errorf("%w: key file size is invalid", ErrInvalid)
	}
	return data, info, nil
}

func marshalPublicSet(keys []jose.JSONWebKey) ([]byte, error) {
	public := make([]jose.JSONWebKey, len(keys))
	for index := range keys {
		if !keys[index].IsPublic() {
			return nil, ErrInvalid
		}
		public[index] = keys[index]
	}
	return marshalIndented(jose.JSONWebKeySet{Keys: public})
}

func marshalIndented(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func writeExclusive(path string, content []byte, mode os.FileMode) (err error) {
	if strings.TrimSpace(path) == "" {
		return ErrInvalid
	}
	// #nosec G304 -- the explicit CLI output path is the intended boundary;
	// O_EXCL, fixed permissions, cleanup, and fsync prevent unsafe replacement.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return ErrExists
	}
	if err != nil {
		return errors.New("key output could not be created")
	}
	complete := false
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = errors.New("key output could not be closed")
		}
		if !complete || err != nil {
			_ = os.Remove(path)
		}
	}()
	if err = file.Chmod(mode); err != nil {
		return errors.New("key output permissions could not be set")
	}
	if _, err = file.Write(content); err != nil {
		return errors.New("key output could not be written")
	}
	if err = file.Sync(); err != nil {
		return errors.New("key output could not be synchronized")
	}
	complete = true
	return nil
}
