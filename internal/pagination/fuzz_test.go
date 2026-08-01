package pagination

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func FuzzOpaqueCursor(f *testing.F) {
	f.Add("")
	f.Add("not-a-cursor")
	f.Add("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add(Encode(Cursor{Time: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), ID: uuid.MustParse("11111111-1111-4111-8111-111111111111")}))

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		cursor, err := Decode(raw)
		if err != nil {
			return
		}
		if raw == "" {
			if !cursor.Time.IsZero() || cursor.ID != uuid.Nil {
				t.Fatal("empty cursor decoded to a non-zero position")
			}
			return
		}
		if encoded := Encode(cursor); encoded != raw {
			t.Fatal("accepted cursor was not canonical")
		}
	})
}
