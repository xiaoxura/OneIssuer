package identity

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	minUsernameRunes = 3
	maxUsernameRunes = 64
	maxDisplayRunes  = 128
	maxEmailBytes    = 320
)

var fold = cases.Fold()

// NormalizeUsername applies the frozen phase-two rule: trim Unicode edge
// whitespace, NFC-normalize, then Unicode case-fold for lookup/uniqueness.
func NormalizeUsername(raw string) (display, normalized string, err error) {
	display = norm.NFC.String(strings.TrimSpace(raw))
	if !utf8.ValidString(display) {
		return "", "", &ValidationError{Field: "username", Code: "invalid_utf8"}
	}
	runes := []rune(display)
	if len(runes) < minUsernameRunes || len(runes) > maxUsernameRunes {
		return "", "", &ValidationError{Field: "username", Code: "invalid_length"}
	}
	for index, value := range runes {
		allowed := unicode.IsLetter(value) || unicode.IsDigit(value) || value == '.' || value == '_' || value == '-'
		if !allowed || ((index == 0 || index == len(runes)-1) && !unicode.IsLetter(value) && !unicode.IsDigit(value)) {
			return "", "", &ValidationError{Field: "username", Code: "invalid_format"}
		}
	}
	normalized = fold.String(display)
	return display, normalized, nil
}

// NormalizeEmail performs no provider-specific rewriting: trim/NFC, validate a
// plain addr-spec, and case-fold the local part while lower-casing the domain.
// The chosen local-part folding prevents ambiguous username-or-email login and
// is recorded in the phase-two ADR.
func NormalizeEmail(raw string) (display, normalized string, err error) {
	display = norm.NFC.String(strings.TrimSpace(raw))
	if !utf8.ValidString(display) || len(display) > maxEmailBytes {
		return "", "", &ValidationError{Field: "email", Code: "invalid_format"}
	}
	parsed, parseErr := mail.ParseAddress(display)
	if parseErr != nil || parsed.Address != display {
		return "", "", &ValidationError{Field: "email", Code: "invalid_format"}
	}
	at := strings.LastIndexByte(display, '@')
	if at <= 0 || at == len(display)-1 || strings.Contains(display[:at], "@") {
		return "", "", &ValidationError{Field: "email", Code: "invalid_format"}
	}
	local := fold.String(display[:at])
	domain := strings.ToLower(display[at+1:])
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || !strings.Contains(domain, ".") {
		return "", "", &ValidationError{Field: "email", Code: "invalid_format"}
	}
	normalized = local + "@" + domain
	return display, normalized, nil
}

// NormalizeLoginIdentifier chooses the only two supported namespaces. Usernames
// cannot contain @, so there is no heuristic overlap.
func NormalizeLoginIdentifier(raw string) (string, error) {
	if strings.Contains(raw, "@") {
		_, normalized, err := NormalizeEmail(raw)
		return normalized, err
	}
	_, normalized, err := NormalizeUsername(raw)
	return normalized, err
}

func normalizeDisplayName(raw, fallback string) (string, error) {
	value := norm.NFC.String(strings.TrimSpace(raw))
	if value == "" {
		value = fallback
	}
	if !utf8.ValidString(value) || len([]rune(value)) > maxDisplayRunes {
		return "", &ValidationError{Field: "display_name", Code: "invalid_length"}
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", &ValidationError{Field: "display_name", Code: "invalid_format"}
		}
	}
	return value, nil
}
