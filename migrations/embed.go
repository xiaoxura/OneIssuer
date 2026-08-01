// Package migrations exposes the immutable production migration set embedded
// into every OneIssuer binary. Both `migrate` and `serve` consume this exact
// filesystem so schema compatibility never depends on runtime files.
package migrations

import (
	"embed"
	"io/fs"
)

// embedded contains production migrations only. Test fixtures deliberately
// live below internal/ and therefore cannot be included here.
//
//go:embed *.sql
var embedded embed.FS

// FS is the read-only production migration filesystem.
var FS fs.FS = embedded
