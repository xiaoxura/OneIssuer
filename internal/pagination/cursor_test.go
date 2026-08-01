package pagination

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCursorRoundTripAndBounds(t *testing.T) {
	t.Parallel()
	want := Cursor{Time: time.Date(2026, 8, 1, 1, 2, 3, 4, time.UTC), ID: uuid.New()}
	got, err := Decode(Encode(want))
	if err != nil || !got.Time.Equal(want.Time) || got.ID != want.ID {
		t.Fatalf("cursor got=%+v err=%v", got, err)
	}
	if _, err := Decode("email@example.invalid"); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("unsafe cursor error=%v", err)
	}
	if Limit(0) != 20 || Limit(500) != 100 {
		t.Fatal("page limits are not bounded")
	}
}
