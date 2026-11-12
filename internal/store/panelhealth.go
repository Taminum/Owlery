package store

import (
	"context"
	"time"
)

// AlertPanelBackup: the nightly dump of the database did not report in. It belongs to no panel.
const AlertPanelBackup = "panel_backup"

type BackupRow struct {
	TakenAt time.Time `json:"taken_at"`
	Bytes   int64     `json:"bytes"`
	OK      bool      `json:"ok"`
}

type DBSample struct {
	Day   string `json:"day"`
	Bytes int64  `json:"bytes"`
}

// RecentBackups returns the last reports of the dump, newest first.
func (s *Store) RecentBackups(ctx context.Context, n int) ([]BackupRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT taken_at, bytes, ok FROM panel_backups ORDER BY taken_at DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BackupRow{}
	for rows.Next() {
		var b BackupRow
		if err := rows.Scan(&b.TakenAt, &b.Bytes, &b.OK); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// SampleDBSize writes today's size of the database (once a day: a later call the same day replaces it) and
// forgets samples older than a year.
func (s *Store) SampleDBSize(ctx context.Context, now time.Time) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO panel_db_samples (day, db_bytes) VALUES ($1::date, pg_database_size(current_database()))
		ON CONFLICT (day) DO UPDATE SET db_bytes = EXCLUDED.db_bytes`, now.UTC().Format("2006-01-02")); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM panel_db_samples WHERE day < $1::date - 365`, now.UTC().Format("2006-01-02"))
	return err
}

// DBSamples returns the last n days of sizes, oldest first.
func (s *Store) DBSamples(ctx context.Context, n int) ([]DBSample, error) {
	rows, err := s.pool.Query(ctx, `SELECT to_char(day, 'YYYY-MM-DD'), db_bytes FROM (SELECT day, db_bytes FROM panel_db_samples ORDER BY day DESC LIMIT $1) x ORDER BY day`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DBSample{}
	for rows.Next() {
		var d DBSample
		if err := rows.Scan(&d.Day, &d.Bytes); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// BackupAlertState is what the alert needs: when the last dump reported, and whether any ever did. A panel that has
// never had a report (an older install without the new backup.sh) says nothing rather than crying at once.
func (s *Store) BackupAlertState(ctx context.Context) (last *time.Time, lastOK *time.Time, err error) {
	err = s.pool.QueryRow(ctx, `SELECT max(taken_at), max(taken_at) FILTER (WHERE ok) FROM panel_backups`).Scan(&last, &lastOK)
	return
}
