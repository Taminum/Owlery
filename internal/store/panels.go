package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/RemnaScope/internal/secrets"
)

type SyncOptions struct {
	Nodes bool `json:"nodes"`
	Users bool `json:"users"`
	Stats bool `json:"stats"`
}

type Panel struct {
	ID                  string
	Name                string
	BaseURL             string
	Status              string
	Demo                bool
	UseCustomCA         bool
	SyncOptions         SyncOptions
	SyncIntervalSeconds int
	RetentionDays       int
	APIVersion          *string
	Capabilities        json.RawMessage
	LastProbeAt         *time.Time
	LastProbe           json.RawMessage
	LastSyncAt          *time.Time
	LastSyncStatus      *string
	NextSyncAt          *time.Time
	ConsecutiveFailures int
	CircuitOpenUntil    *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	NodeCount           int
	UserCount           int
	HasCredential       bool
}

const panelCols = `p.id, p.name, p.base_url, p.status, p.demo, p.use_custom_ca, p.sync_options, p.sync_interval_seconds, p.retention_days,
	p.api_version, p.capabilities, p.last_probe_at, p.last_probe, p.last_sync_at, p.last_sync_status, p.next_sync_at,
	p.consecutive_failures, p.circuit_open_until, p.created_at, p.updated_at,
	(SELECT count(*) FROM nodes n WHERE n.panel_id=p.id AND n.removed_at IS NULL),
	(SELECT count(*) FROM users u WHERE u.panel_id=p.id AND u.removed_at IS NULL),
	EXISTS (SELECT 1 FROM panel_credentials c WHERE c.panel_id=p.id)`

func scanPanel(r pgx.Row) (Panel, error) {
	var p Panel
	var id uuid.UUID
	var opts []byte
	err := r.Scan(&id, &p.Name, &p.BaseURL, &p.Status, &p.Demo, &p.UseCustomCA, &opts, &p.SyncIntervalSeconds, &p.RetentionDays,
		&p.APIVersion, &p.Capabilities, &p.LastProbeAt, &p.LastProbe, &p.LastSyncAt, &p.LastSyncStatus, &p.NextSyncAt,
		&p.ConsecutiveFailures, &p.CircuitOpenUntil, &p.CreatedAt, &p.UpdatedAt, &p.NodeCount, &p.UserCount, &p.HasCredential)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.ID = id.String()
	_ = json.Unmarshal(opts, &p.SyncOptions)
	return p, nil
}

type PanelInput struct {
	Name                string
	BaseURL             string
	Demo                bool
	UseCustomCA         bool
	SyncOptions         SyncOptions
	SyncIntervalSeconds int
	RetentionDays       int
	Status              string
	APIVersion          *string
	Capabilities        json.RawMessage
	LastProbe           json.RawMessage
}

func NewPanelID() string { return uuid.NewString() }

// CreatePanel inserts a panel and, when cred is set, its sealed token in one transaction.
func (s *Store) CreatePanel(ctx context.Context, id string, in PanelInput, cred *secrets.Sealed) (Panel, error) {
	pid, err := ParseID(id)
	if err != nil {
		return Panel{}, err
	}
	if in.Status == "" {
		in.Status = "active"
	}
	if in.SyncIntervalSeconds == 0 {
		in.SyncIntervalSeconds = 300
	}
	if in.RetentionDays == 0 {
		in.RetentionDays = 30
	}
	opts, _ := json.Marshal(in.SyncOptions)
	caps := in.Capabilities
	if len(caps) == 0 {
		caps = json.RawMessage(`{}`)
	}
	next := s.now()
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var probeAt *time.Time
		if len(in.LastProbe) > 0 {
			t := s.now()
			probeAt = &t
		}
		_, err := tx.Exec(ctx, `INSERT INTO panels (id, name, base_url, status, demo, use_custom_ca, sync_options, sync_interval_seconds, retention_days,
			api_version, capabilities, last_probe, last_probe_at, next_sync_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			pid, in.Name, in.BaseURL, in.Status, in.Demo, in.UseCustomCA, opts, in.SyncIntervalSeconds, in.RetentionDays,
			in.APIVersion, caps, nullJSON(in.LastProbe), probeAt, next)
		if err != nil {
			return err
		}
		if cred != nil {
			_, err = tx.Exec(ctx, `INSERT INTO panel_credentials (panel_id, ciphertext, nonce, key_version) VALUES ($1,$2,$3,$4)`,
				pid, cred.Ciphertext, cred.Nonce, cred.KeyVersion)
		}
		return err
	})
	if IsUniqueViolation(err) {
		return Panel{}, ErrConflict
	}
	if err != nil {
		return Panel{}, err
	}
	return s.panelUnscoped(ctx, pid)
}

func nullJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return []byte(b)
}

func (s *Store) panelUnscoped(ctx context.Context, id uuid.UUID) (Panel, error) {
	return scanPanel(s.pool.QueryRow(ctx, `SELECT `+panelCols+` FROM panels p WHERE p.id=$1 AND p.deleted_at IS NULL`, id))
}

// GetPanel returns ErrNotFound for panels outside the scope, so existence is never revealed.
func (s *Store) GetPanel(ctx context.Context, sc Scope, id string) (Panel, error) {
	pid, err := ParseID(id)
	if err != nil {
		return Panel{}, err
	}
	if !sc.Allows(id) {
		return Panel{}, ErrNotFound
	}
	return s.panelUnscoped(ctx, pid)
}

func (s *Store) ListPanels(ctx context.Context, sc Scope) ([]Panel, error) {
	pred, args := sc.predicate("p.id", 0)
	rows, err := s.pool.Query(ctx, `SELECT `+panelCols+` FROM panels p WHERE p.deleted_at IS NULL AND `+pred+` ORDER BY p.demo, lower(p.name)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Panel
	for rows.Next() {
		p, err := scanPanel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type PanelPatch struct {
	Name                *string
	SyncOptions         *SyncOptions
	SyncIntervalSeconds *int
	RetentionDays       *int
	UseCustomCA         *bool
}

func (s *Store) UpdatePanel(ctx context.Context, sc Scope, id string, pt PanelPatch) (Panel, error) {
	pid, err := ParseID(id)
	if err != nil || !sc.Allows(id) {
		return Panel{}, ErrNotFound
	}
	var opts any
	if pt.SyncOptions != nil {
		b, _ := json.Marshal(pt.SyncOptions)
		opts = b
	}
	tag, err := s.pool.Exec(ctx, `UPDATE panels SET
			name = COALESCE($2, name),
			sync_options = COALESCE($3::jsonb, sync_options),
			sync_interval_seconds = COALESCE($4, sync_interval_seconds),
			retention_days = COALESCE($5, retention_days),
			use_custom_ca = COALESCE($6, use_custom_ca),
			updated_at = now()
		WHERE id=$1 AND deleted_at IS NULL`, pid, pt.Name, opts, pt.SyncIntervalSeconds, pt.RetentionDays, pt.UseCustomCA)
	if IsUniqueViolation(err) {
		return Panel{}, ErrConflict
	}
	if err != nil {
		return Panel{}, err
	}
	if tag.RowsAffected() == 0 {
		return Panel{}, ErrNotFound
	}
	return s.panelUnscoped(ctx, pid)
}

func (s *Store) SetPanelStatus(ctx context.Context, id, status string) error {
	pid, err := ParseID(id)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE panels SET status=$2, updated_at=now(),
		next_sync_at = CASE WHEN $2='active' THEN now() ELSE next_sync_at END,
		consecutive_failures = CASE WHEN $2='active' THEN 0 ELSE consecutive_failures END,
		circuit_open_until = CASE WHEN $2='active' THEN NULL ELSE circuit_open_until END
		WHERE id=$1 AND deleted_at IS NULL`, pid, status)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) SavePanelProbe(ctx context.Context, id string, apiVersion *string, capabilities, probe json.RawMessage) error {
	pid, err := ParseID(id)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE panels SET api_version=$2, capabilities=$3, last_probe=$4, last_probe_at=now(), updated_at=now() WHERE id=$1`,
		pid, apiVersion, capabilities, probe)
	return err
}

// DeletePanel either hard-deletes everything synced for the panel (purge) or hides it
// and wipes its credential while keeping the data until retention expires (archive).
// Audit history is kept in both cases.
func (s *Store) DeletePanel(ctx context.Context, id, mode string) error {
	pid, err := ParseID(id)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM panels WHERE id=$1 AND deleted_at IS NULL)`, pid).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		switch mode {
		case "purge":
			_, err = tx.Exec(ctx, `DELETE FROM panels WHERE id=$1`, pid)
		case "archive":
			if _, err = tx.Exec(ctx, `DELETE FROM panel_credentials WHERE panel_id=$1`, pid); err == nil {
				// Free the name for reuse: the unique index only covers live panels.
				_, err = tx.Exec(ctx, `UPDATE panels SET deleted_at=now(), status='disabled', updated_at=now() WHERE id=$1`, pid)
			}
		default:
			return errors.New("store: unknown delete mode")
		}
		return err
	})
}

// --- credentials -----------------------------------------------------------

func (s *Store) Credential(ctx context.Context, panelID string) (secrets.Sealed, error) {
	pid, err := ParseID(panelID)
	if err != nil {
		return secrets.Sealed{}, err
	}
	var sl secrets.Sealed
	err = s.pool.QueryRow(ctx, `SELECT ciphertext, nonce, key_version FROM panel_credentials WHERE panel_id=$1`, pid).
		Scan(&sl.Ciphertext, &sl.Nonce, &sl.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return sl, ErrNotFound
	}
	return sl, err
}

func (s *Store) PutCredential(ctx context.Context, panelID string, sl secrets.Sealed) error {
	pid, err := ParseID(panelID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO panel_credentials (panel_id, ciphertext, nonce, key_version) VALUES ($1,$2,$3,$4)
		ON CONFLICT (panel_id) DO UPDATE SET ciphertext=$2, nonce=$3, key_version=$4, updated_at=now()`,
		pid, sl.Ciphertext, sl.Nonce, sl.KeyVersion)
	return err
}

type CredentialRef struct {
	PanelID string
	Sealed  secrets.Sealed
}

func (s *Store) AllCredentials(ctx context.Context) ([]CredentialRef, error) {
	rows, err := s.pool.Query(ctx, `SELECT panel_id, ciphertext, nonce, key_version FROM panel_credentials ORDER BY panel_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CredentialRef
	for rows.Next() {
		var id uuid.UUID
		var r CredentialRef
		if err := rows.Scan(&id, &r.Sealed.Ciphertext, &r.Sealed.Nonce, &r.Sealed.KeyVersion); err != nil {
			return nil, err
		}
		r.PanelID = id.String()
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReplaceCredentialIf swaps a credential only if it is still at oldVersion, so a
// concurrent token rotation is never overwritten by a key rotation.
func (s *Store) ReplaceCredentialIf(ctx context.Context, panelID string, oldVersion int, sl secrets.Sealed) (bool, error) {
	pid, err := ParseID(panelID)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE panel_credentials SET ciphertext=$3, nonce=$4, key_version=$5, updated_at=now()
		WHERE panel_id=$1 AND key_version=$2`, pid, oldVersion, sl.Ciphertext, sl.Nonce, sl.KeyVersion)
	return tag.RowsAffected() == 1, err
}

// --- nodes and users ---------------------------------------------------------

type NodeRecord struct {
	RemoteUUID       string
	Name             string
	CountryCode      string
	XrayVersion      string
	IsConnected      *bool
	IsDisabled       *bool
	UsersOnline      *int
	LastStatusChange *time.Time
}

type Node struct {
	ID               string     `json:"id"`
	PanelID          string     `json:"panel_id"`
	RemoteUUID       string     `json:"remote_uuid"`
	Name             string     `json:"name"`
	CountryCode      *string    `json:"country_code"`
	XrayVersion      *string    `json:"xray_version"`
	IsConnected      *bool      `json:"is_connected"`
	IsDisabled       *bool      `json:"is_disabled"`
	UsersOnline      *int       `json:"users_online"`
	LastStatusChange *time.Time `json:"last_status_change"`
	LastSyncAt       *time.Time `json:"last_sync_at"`
	RemovedAt        *time.Time `json:"removed_at"`
}

type SyncCounts struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Removed int `json:"removed"`
	Skipped int `json:"skipped,omitempty"`
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// UpsertNodes records the full node list seen at runStart and marks nodes that
// disappeared from the panel. Every row is keyed by (panel_id, remote_uuid), so two
// panels reporting the same remote UUID never touch each other's rows.
func (s *Store) UpsertNodes(ctx context.Context, panelID string, runStart time.Time, nodes []NodeRecord) (SyncCounts, error) {
	pid, err := ParseID(panelID)
	if err != nil {
		return SyncCounts{}, err
	}
	var c SyncCounts
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		for _, n := range nodes {
			var inserted bool
			err := tx.QueryRow(ctx, `INSERT INTO nodes (panel_id, remote_uuid, name, country_code, xray_version, is_connected, is_disabled, users_online, last_status_change, last_sync_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
				ON CONFLICT (panel_id, remote_uuid) DO UPDATE SET name=EXCLUDED.name, country_code=EXCLUDED.country_code, xray_version=EXCLUDED.xray_version,
					is_connected=EXCLUDED.is_connected, is_disabled=EXCLUDED.is_disabled, users_online=EXCLUDED.users_online,
					last_status_change=EXCLUDED.last_status_change, last_sync_at=EXCLUDED.last_sync_at, removed_at=NULL
				RETURNING (xmax = 0)`,
				pid, n.RemoteUUID, n.Name, nilIfEmpty(n.CountryCode), nilIfEmpty(n.XrayVersion), n.IsConnected, n.IsDisabled, n.UsersOnline, n.LastStatusChange, runStart).Scan(&inserted)
			if err != nil {
				return err
			}
			if inserted {
				c.Added++
			} else {
				c.Updated++
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE nodes SET removed_at=$2 WHERE panel_id=$1 AND removed_at IS NULL AND (last_sync_at IS NULL OR last_sync_at < $2)`, pid, runStart)
		c.Removed = int(tag.RowsAffected())
		return err
	})
	return c, err
}

func (s *Store) ListNodes(ctx context.Context, sc Scope, panelID string, includeRemoved bool) ([]Node, error) {
	pid, err := ParseID(panelID)
	if err != nil || !sc.Allows(panelID) {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT id, panel_id, remote_uuid, name, country_code, xray_version, is_connected, is_disabled, users_online, last_status_change, last_sync_at, removed_at
		FROM nodes WHERE panel_id=$1 AND ($2 OR removed_at IS NULL) ORDER BY lower(name)`, pid, includeRemoved)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var id, p uuid.UUID
		if err := rows.Scan(&id, &p, &n.RemoteUUID, &n.Name, &n.CountryCode, &n.XrayVersion, &n.IsConnected, &n.IsDisabled, &n.UsersOnline, &n.LastStatusChange, &n.LastSyncAt, &n.RemovedAt); err != nil {
			return nil, err
		}
		n.ID, n.PanelID = id.String(), p.String()
		out = append(out, n)
	}
	return out, rows.Err()
}

type UserRecord struct {
	RemoteUUID string
	Username   string
	Status     string
}

type User struct {
	ID         string     `json:"id"`
	PanelID    string     `json:"panel_id"`
	RemoteUUID string     `json:"remote_uuid"`
	Username   *string    `json:"username"`
	Status     *string    `json:"status"`
	LastSyncAt *time.Time `json:"last_sync_at"`
}

func (s *Store) UpsertUsers(ctx context.Context, panelID string, runStart time.Time, users []UserRecord) (SyncCounts, error) {
	pid, err := ParseID(panelID)
	if err != nil {
		return SyncCounts{}, err
	}
	var c SyncCounts
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		for _, u := range users {
			var inserted bool
			err := tx.QueryRow(ctx, `INSERT INTO users (panel_id, remote_uuid, display_name, status, last_sync_at) VALUES ($1,$2,$3,$4,$5)
				ON CONFLICT (panel_id, remote_uuid) DO UPDATE SET display_name=EXCLUDED.display_name, status=EXCLUDED.status, last_sync_at=EXCLUDED.last_sync_at, removed_at=NULL
				RETURNING (xmax = 0)`, pid, u.RemoteUUID, nilIfEmpty(u.Username), nilIfEmpty(u.Status), runStart).Scan(&inserted)
			if err != nil {
				return err
			}
			if inserted {
				c.Added++
			} else {
				c.Updated++
			}
		}
		return nil
	})
	return c, err
}

// MarkUsersRemoved is called only after a listing was read to the end.
func (s *Store) MarkUsersRemoved(ctx context.Context, panelID string, runStart time.Time) (int, error) {
	pid, err := ParseID(panelID)
	if err != nil {
		return 0, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE users SET removed_at=$2 WHERE panel_id=$1 AND removed_at IS NULL AND (last_sync_at IS NULL OR last_sync_at < $2)`, pid, runStart)
	return int(tag.RowsAffected()), err
}

// ListUsers is keyset-paginated on id. The caller decides whether to mask usernames.
func (s *Store) ListUsers(ctx context.Context, sc Scope, panelID, after string, limit int) ([]User, string, error) {
	pid, err := ParseID(panelID)
	if err != nil || !sc.Allows(panelID) {
		return nil, "", ErrNotFound
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	afterID := uuid.Nil
	if after != "" {
		if afterID, err = uuid.Parse(after); err != nil {
			return nil, "", ErrNotFound
		}
	}
	rows, err := s.pool.Query(ctx, `SELECT id, panel_id, remote_uuid, display_name, status, last_sync_at FROM users
		WHERE panel_id=$1 AND removed_at IS NULL AND id > $2 ORDER BY id LIMIT $3`, pid, afterID, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var id, p uuid.UUID
		if err := rows.Scan(&id, &p, &u.RemoteUUID, &u.Username, &u.Status, &u.LastSyncAt); err != nil {
			return nil, "", err
		}
		u.ID, u.PanelID = id.String(), p.String()
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[limit-1].ID
	}
	return out, next, nil
}

// --- sync bookkeeping ------------------------------------------------------

type SyncRun struct {
	ID         string          `json:"id"`
	PanelID    string          `json:"panel_id"`
	Operation  string          `json:"operation"`
	Trigger    string          `json:"trigger"`
	Status     string          `json:"status"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	ErrorCode  *string         `json:"error_code"`
	Detail     *string         `json:"detail"`
	Stats      json.RawMessage `json:"stats"`
}

func (s *Store) StartSyncRun(ctx context.Context, panelID, operation, trigger string) (string, error) {
	pid, err := ParseID(panelID)
	if err != nil {
		return "", err
	}
	var id uuid.UUID
	err = s.pool.QueryRow(ctx, `INSERT INTO sync_runs (panel_id, operation, status, trigger) VALUES ($1,$2,'running',$3) RETURNING id`, pid, operation, trigger).Scan(&id)
	return id.String(), err
}

func (s *Store) FinishSyncRun(ctx context.Context, runID, status, errCode, detail string, stats any) error {
	rid, err := ParseID(runID)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(stats)
	_, err = s.pool.Exec(ctx, `UPDATE sync_runs SET status=$2, finished_at=now(), error_code=$3, detail=$4, stats=$5 WHERE id=$1`,
		rid, status, nilIfEmpty(errCode), nilIfEmpty(detail), b)
	return err
}

func (s *Store) ListSyncRuns(ctx context.Context, sc Scope, panelID string, limit int) ([]SyncRun, error) {
	pid, err := ParseID(panelID)
	if err != nil || !sc.Allows(panelID) {
		return nil, ErrNotFound
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `SELECT id, panel_id, operation, trigger, status, started_at, finished_at, error_code, detail, stats
		FROM sync_runs WHERE panel_id=$1 ORDER BY started_at DESC LIMIT $2`, pid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SyncRun
	for rows.Next() {
		var r SyncRun
		var id, p uuid.UUID
		if err := rows.Scan(&id, &p, &r.Operation, &r.Trigger, &r.Status, &r.StartedAt, &r.FinishedAt, &r.ErrorCode, &r.Detail, &r.Stats); err != nil {
			return nil, err
		}
		r.ID, r.PanelID = id.String(), p.String()
		out = append(out, r)
	}
	return out, rows.Err()
}

// DuePanels lists live, non-demo panels whose next sync time has come and whose circuit is closed.
func (s *Store) DuePanels(ctx context.Context, now time.Time, limit int) ([]Panel, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+panelCols+` FROM panels p
		WHERE p.deleted_at IS NULL AND NOT p.demo AND p.status IN ('active','error')
		  AND EXISTS (SELECT 1 FROM panel_credentials c WHERE c.panel_id=p.id)
		  AND (p.next_sync_at IS NULL OR p.next_sync_at <= $1)
		  AND (p.circuit_open_until IS NULL OR p.circuit_open_until <= $1)
		ORDER BY p.next_sync_at NULLS FIRST LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Panel
	for rows.Next() {
		p, err := scanPanel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RecordSyncOutcome updates scheduling state after a run. Failures back off
// exponentially with the panel's interval as the base; enough consecutive failures
// open the circuit for a cool-down so a dead panel is not hammered.
func (s *Store) RecordSyncOutcome(ctx context.Context, panelID string, ok bool, status string, interval time.Duration, now time.Time, retryAfter time.Duration, breakerAfter int, breakerFor time.Duration) error {
	pid, err := ParseID(panelID)
	if err != nil {
		return err
	}
	if ok {
		_, err = s.pool.Exec(ctx, `UPDATE panels SET status='active', consecutive_failures=0, circuit_open_until=NULL, last_sync_at=$2, last_sync_status=$3, next_sync_at=$4, updated_at=now() WHERE id=$1`,
			pid, now, status, now.Add(interval))
		return err
	}
	var failures int
	if err := s.pool.QueryRow(ctx, `UPDATE panels SET consecutive_failures=consecutive_failures+1, last_sync_status=$2 WHERE id=$1 RETURNING consecutive_failures`, pid, status).Scan(&failures); err != nil {
		return err
	}
	backoff := interval << uint(min(failures, 6))
	if backoff > time.Hour {
		backoff = time.Hour
	}
	if retryAfter > backoff {
		backoff = retryAfter
	}
	var open any
	if failures >= breakerAfter {
		open = now.Add(breakerFor)
	}
	_, err = s.pool.Exec(ctx, `UPDATE panels SET status='error', next_sync_at=$2, circuit_open_until=$3, updated_at=now() WHERE id=$1`, pid, now.Add(backoff), open)
	return err
}

// ScheduleNow makes a panel due immediately (manual sync) without touching its failure counters.
func (s *Store) ScheduleNow(ctx context.Context, panelID string) error {
	pid, err := ParseID(panelID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE panels SET next_sync_at=now() WHERE id=$1 AND deleted_at IS NULL`, pid)
	return err
}

// --- audit ---------------------------------------------------------------

type AuditEntry struct {
	ActorID    string
	ActorName  string
	PanelID    string
	Action     string
	ObjectType string
	ObjectID   string
	IP         string
	RequestID  string
	Metadata   map[string]any
}

// WriteAudit records an action. Metadata must never contain secrets; callers pass
// names, counts and codes only.
func (s *Store) WriteAudit(ctx context.Context, e AuditEntry) error {
	var actor, panel any
	if u, err := uuid.Parse(e.ActorID); err == nil {
		actor = u
	}
	if u, err := uuid.Parse(e.PanelID); err == nil {
		panel = u
	}
	var ip any
	if e.IP != "" {
		ip = e.IP
	}
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	mb, _ := json.Marshal(meta)
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_log (actor_id, actor_name, panel_id, action, object_type, object_id, ip, request_id, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7::inet,$8,$9)`, actor, nilIfEmpty(e.ActorName), panel, e.Action, e.ObjectType, nilIfEmpty(e.ObjectID), ip, nilIfEmpty(e.RequestID), mb)
	return err
}

type AuditRow struct {
	ID         string          `json:"id"`
	ActorName  *string         `json:"actor_name"`
	PanelID    *string         `json:"panel_id"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   *string         `json:"object_id"`
	TS         time.Time       `json:"ts"`
	RequestID  *string         `json:"request_id"`
	Metadata   json.RawMessage `json:"metadata"`
}

// ListAudit returns newest-first entries visible in scope. Entries without a panel
// (logins, account changes) are visible to owners only.
func (s *Store) ListAudit(ctx context.Context, sc Scope, panelID string, before time.Time, limit int) ([]AuditRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if before.IsZero() {
		before = s.now().Add(time.Minute)
	}
	args := []any{before, limit}
	where := "ts < $1"
	if panelID != "" {
		pid, err := ParseID(panelID)
		if err != nil || !sc.Allows(panelID) {
			return nil, ErrNotFound
		}
		args = append(args, pid)
		where += " AND panel_id = $3"
	} else if !sc.All {
		pred, a := sc.predicate("panel_id", 2)
		where += " AND " + pred
		args = append(args, a...)
	}
	rows, err := s.pool.Query(ctx, `SELECT id, actor_name, panel_id, action, object_type, object_id, ts, request_id, metadata FROM audit_log WHERE `+where+` ORDER BY ts DESC LIMIT $2`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		var id uuid.UUID
		var pid *uuid.UUID
		if err := rows.Scan(&id, &r.ActorName, &pid, &r.Action, &r.ObjectType, &r.ObjectID, &r.TS, &r.RequestID, &r.Metadata); err != nil {
			return nil, err
		}
		r.ID = id.String()
		if pid != nil {
			s := pid.String()
			r.PanelID = &s
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
