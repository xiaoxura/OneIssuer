package keystore

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestGenerateLoadSignAndPublish(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "active.jwk")
	metadata, err := Generate(privatePath, 2048, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private mode=%v", info.Mode().Perm())
	}
	store, err := Load(privatePath, "")
	if err != nil {
		t.Fatal(err)
	}
	if store.Metadata() != metadata || len(store.PublicKeys()) != 1 || store.ETag() == "" {
		t.Fatalf("metadata=%+v generated=%+v", store.Metadata(), metadata)
	}
	jwks := string(store.PublicJWKS())
	for _, forbidden := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(jwks, forbidden) {
			t.Fatalf("public JWKS contains private member %s: %s", forbidden, jwks)
		}
	}
	payload := []byte(`{"sub":"subject"}`)
	compact, err := store.Sign(payload, "JWT")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(signature.Signatures) != 1 {
		t.Fatalf("parse signature err=%v", err)
	}
	if signature.Signatures[0].Header.KeyID != metadata.ActiveKeyID || signature.Signatures[0].Header.ExtraHeaders[jose.HeaderType] != "JWT" {
		t.Fatalf("protected header=%+v", signature.Signatures[0].Header)
	}
	verified, err := signature.Verify(store.PublicKeys()[0].Key)
	if err != nil || string(verified) != string(payload) {
		t.Fatalf("verify payload=%q err=%v", verified, err)
	}
	if _, err := store.Sign(payload, "unexpected"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsupported typ error=%v", err)
	}
}

func TestLoadRejectsBroadModeAndSymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "active.jwk")
	if _, err := Generate(privatePath, 2048, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(privatePath, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("broad mode error=%v", err)
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link.jwk")
	if err := os.Symlink(privatePath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(symlink, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink error=%v", err)
	}
}

func TestGenerateRefusesOverwriteAndWritesPublicOnly(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "active.jwk")
	if _, err := Generate(privatePath, 2048, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(privatePath, 2048, rand.Reader); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite error=%v", err)
	}
	publicPath := filepath.Join(directory, "public.jwks")
	metadata, err := WritePublic(privatePath, publicPath)
	if err != nil || metadata.PublishedKeys != 1 {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	encoded, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(encoded, &set); err != nil || len(set.Keys) != 1 || !set.Keys[0].IsPublic() {
		t.Fatalf("public set=%+v err=%v", set, err)
	}
	if _, err := WritePublic(privatePath, publicPath); !errors.Is(err, ErrExists) {
		t.Fatalf("public overwrite error=%v", err)
	}
}

func TestVerificationRingRequiresPublicUniqueThumbprints(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	activePath := filepath.Join(directory, "active.jwk")
	oldPath := filepath.Join(directory, "old.jwk")
	if _, err := Generate(activePath, 2048, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(oldPath, 2048, rand.Reader); err != nil {
		t.Fatal(err)
	}
	old, err := loadPrivate(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	setPath := filepath.Join(directory, "verification.jwks")
	encoded, err := marshalPublicSet([]jose.JSONWebKey{old.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(setPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Load(activePath, setPath)
	if err != nil || store.Metadata().PublishedKeys != 2 {
		t.Fatalf("metadata=%+v err=%v", store.Metadata(), err)
	}

	active, err := loadPrivate(activePath)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := marshalPublicSet([]jose.JSONWebKey{active.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(setPath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(activePath, setPath); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate ring error=%v", err)
	}

	privateSet, err := marshalIndented(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{old}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(setPath, privateSet, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(activePath, setPath); !errors.Is(err, ErrInvalid) {
		t.Fatalf("private verification key error=%v", err)
	}
}
