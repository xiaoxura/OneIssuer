// Package pagination implements the opaque, stable time/UUID cursor shared by
// phase-two administrative lists. No user identifier or email is encoded.
package pagination

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrInvalidCursor identifies a malformed, unsupported, or out-of-range cursor.
var ErrInvalidCursor = errors.New("invalid pagination cursor")

// Cursor orders rows by (time DESC, UUID DESC).
type Cursor struct {
	Time time.Time
	ID   uuid.UUID
}

// Encode returns a versioned, URL-safe opaque cursor.
func Encode(cursor Cursor) string {
	payload := make([]byte, 25)
	payload[0] = 1
	binary.BigEndian.PutUint64(payload[1:9], uint64(cursor.Time.UTC().UnixNano()))
	copy(payload[9:], cursor.ID[:])
	return base64.RawURLEncoding.EncodeToString(payload)
}

// Decode rejects unknown versions, non-canonical base64, zero IDs, and invalid
// timestamps rather than accepting a best-effort cursor.
func Decode(raw string) (Cursor, error) {
	if raw == "" {
		return Cursor{}, nil
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(payload) != 25 || payload[0] != 1 {
		return Cursor{}, ErrInvalidCursor
	}
	if base64.RawURLEncoding.EncodeToString(payload) != raw {
		return Cursor{}, ErrInvalidCursor
	}
	var id uuid.UUID
	copy(id[:], payload[9:])
	if id == uuid.Nil {
		return Cursor{}, ErrInvalidCursor
	}
	// #nosec G115 -- this is an intentional two's-complement bit reinterpretation
	// matching Encode's int64-to-uint64 representation, not a numeric narrowing.
	nanos := int64(binary.BigEndian.Uint64(payload[1:9]))
	value := time.Unix(0, nanos).UTC()
	if value.Year() < 2000 || value.Year() > 9999 {
		return Cursor{}, ErrInvalidCursor
	}
	return Cursor{Time: value, ID: id}, nil
}

// Limit applies the API's bounded page-size rule.
func Limit(requested int) int {
	if requested <= 0 {
		return 20
	}
	if requested > 100 {
		return 100
	}
	return requested
}
