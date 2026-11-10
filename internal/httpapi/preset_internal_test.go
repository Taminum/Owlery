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

// A page asks for the window the warm-up has had time to count, and moves on to the next one a few minutes after the step.
func TestAPageStaysOnTheReadyWindowUntilTheNextIsCounted(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 11, 10, h, m, 30, 0, time.UTC) }
	for _, c := range []struct {
		now  time.Time
		d    time.Duration
		want string
	}{
		{at(12, 1), 24 * time.Hour, "11:45"}, {at(12, 3), 24 * time.Hour, "11:45"}, {at(12, 4), 24 * time.Hour, "12:00"}, {at(12, 14), 24 * time.Hour, "12:00"},
		{at(12, 1), 7 * 24 * time.Hour, "11:00"}, {at(12, 11), 7 * 24 * time.Hour, "11:00"}, {at(12, 12), 7 * 24 * time.Hour, "12:00"},
		{at(12, 1), time.Hour, "12:01"}, // a short range is small enough to count on the spot
	} {
		if got := pageEnd(c.now, c.d).Format("15:04"); got != c.want {
			t.Errorf("at %s a page of %v ends at %s, want %s", c.now.Format("15:04"), c.d, got, c.want)
		}
		if w := presetEnd(c.now, c.d); pageEnd(c.now, c.d).After(w) {
			t.Errorf("a page ran ahead of the warm-up at %s", c.now.Format("15:04"))
		}
	}
}
