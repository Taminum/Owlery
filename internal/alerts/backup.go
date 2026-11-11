package alerts

import (
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

// BackupStale is how long the nightly dump may stay silent: a day, and a few hours for it to run late.
const BackupStale = 30 * time.Hour

// BackupConditions says when the dump of the database is not reporting or reports a failure. Nothing is said while no
// report has ever arrived (an install whose backup script does not report yet).
func BackupConditions(last, lastOK *time.Time, now time.Time) []store.Condition {
	if last == nil {
		return nil
	}
	if lastOK == nil || now.Sub(*lastOK) > BackupStale {
		detail := "Последняя успешная копия: "
		if lastOK == nil {
			detail = "Успешной копии ещё не было"
		} else {
			detail += minutes(now.Sub(*lastOK)) + " назад"
		}
		return []store.Condition{{Kind: store.AlertPanelBackup, Subject: "panel", Label: "Ночная копия базы Owlery не прошла", Detail: detail}}
	}
	return nil
}
