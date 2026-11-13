package syncer

import (
	"context"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/remnawave"
)

// fakeHistory serves a fixed history in the order it was given, page by page, as the panel does.
type fakeHistory struct {
	all   []remnawave.SubscriptionRequest
	asked []int
}

func (f *fakeHistory) SubscriptionHistory(_ context.Context, start, size int) (remnawave.SubscriptionHistory, error) {
	f.asked = append(f.asked, start)
	end := min(start+size, len(f.all))
	var page []remnawave.SubscriptionRequest
	if start < len(f.all) {
		page = f.all[start:end]
	}
	return remnawave.SubscriptionHistory{Records: page, Total: len(f.all)}, nil
}

func history(n int, newestFirst bool) []remnawave.SubscriptionRequest {
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	out := make([]remnawave.SubscriptionRequest, n)
	for i := range out {
		k := i
		if newestFirst {
			k = n - 1 - i
		}
		out[i] = remnawave.SubscriptionRequest{ID: int64(k + 1), UserID: "2", At: base.Add(time.Duration(k) * time.Minute), IP: "46.0.0.1"}
	}
	return out
}

// collector is a store that remembers the ids it has seen, as the unique key does.
type collector struct{ seen map[int64]bool }

func (c *collector) add(recs []remnawave.SubscriptionRequest) (int64, error) {
	var n int64
	for _, r := range recs {
		if !c.seen[r.ID] {
			c.seen[r.ID] = true
			n++
		}
	}
	return n, nil
}

func TestCopyHistoryReadsFromTheNewestEndWhicheverWayThePanelOrdersIt(t *testing.T) {
	for _, newestFirst := range []bool{true, false} {
		f := &fakeHistory{all: history(2500, newestFirst)}
		c := &collector{seen: map[int64]bool{}}
		if err := copyHistory(context.Background(), f, c.add); err != nil {
			t.Fatal(err)
		}
		if len(c.seen) != 2500 {
			t.Fatalf("newestFirst=%v: copied %d of 2500", newestFirst, len(c.seen))
		}
		// later requests arrive: only the newest end is read again, and it stops at the first page with nothing new
		before := len(f.asked)
		extra := remnawave.SubscriptionRequest{ID: 2501, UserID: "2", At: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), IP: "46.0.0.2"}
		if newestFirst {
			f.all = append([]remnawave.SubscriptionRequest{extra}, f.all...)
		} else {
			f.all = append(f.all, extra)
		}
		if err := copyHistory(context.Background(), f, c.add); err != nil {
			t.Fatal(err)
		}
		if len(c.seen) != 2501 {
			t.Fatalf("newestFirst=%v: the new request was missed (%d)", newestFirst, len(c.seen))
		}
		if used := len(f.asked) - before; used > 4 {
			t.Fatalf("newestFirst=%v: a pass with one new request used %d reads", newestFirst, used)
		}
	}
}
