package alerts

import (
	"testing"
	"time"
)

func TestBackupConditions(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	ago := func(h int) *time.Time { x := now.Add(-time.Duration(h) * time.Hour); return &x }
	if got := BackupConditions(nil, nil, now); len(got) != 0 {
		t.Fatalf("an install that never reported must stay quiet: %v", got)
	}
	if got := BackupConditions(ago(9), ago(9), now); len(got) != 0 {
		t.Fatalf("a fresh good copy: %v", got)
	}
	if got := BackupConditions(ago(2), ago(40), now); len(got) != 1 {
		t.Fatalf("a failure after an old good one must alert: %v", got)
	}
	if got := BackupConditions(ago(2), nil, now); len(got) != 1 || got[0].Detail != "Успешной копии ещё не было" {
		t.Fatalf("only failures so far: %v", got)
	}
}
