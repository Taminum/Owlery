package httpapi

import (
	"testing"
	"time"
)

// The longer the range, the longer the same answer serves: counting a week again every five minutes was a third of
// everything the database did.
func TestALongRangeEndsOnACoarserStep(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 37, 44, 0, time.UTC)
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{15 * time.Minute, "12:37:00"}, {time.Hour, "12:37:00"},
		{24 * time.Hour, "12:30:00"},
		{7 * 24 * time.Hour, "12:00:00"}, {30 * 24 * time.Hour, "12:00:00"},
	} {
		if got := presetEnd(now, c.d).Format("15:04:05"); got != c.want {
			t.Errorf("%v ends at %s, want %s", c.d, got, c.want)
		}
	}
}
