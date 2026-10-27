package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/Owlery/internal/secproto"
)

type SecCommand struct {
	ID          string     `json:"id"`
	VPSID       string     `json:"vps_id"`
	AgentID     string     `json:"agent_id"`
	Action      string     `json:"action"`
	Jail        string     `json:"jail"`
	IP          string     `json:"ip"`
	State       string     `json:"state"`
	RequestedAt time.Time  `json:"requested_at"`
	SentAt      *time.Time `json:"sent_at"`
	Deadline    time.Time  `json:"deadline"`
	FinishedAt  *time.Time `json:"finished_at"`
	ResultCode  *string    `json:"result_code"`
	Verified    bool       `json:"verified"`
	ActorID     *string    `json:"actor_id,omitempty"`
}

const cmdCols = `id, vps_id, agent_id, action, jail, ip, state, requested_at, sent_at, deadline, finished_at, result_code, verified, actor_id`

func scanCmd(r pgx.Row) (SecCommand, error) {
	var c SecCommand
	var id, vid, aid uuid.UUID
	var actor *uuid.UUID
	err := r.Scan(&id, &vid, &aid, &c.Action, &c.Jail, &c.IP, &c.State, &c.RequestedAt, &c.SentAt, &c.Deadline, &c.FinishedAt, &c.ResultCode, &c.Verified, &actor)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	c.ID, c.VPSID, c.AgentID = id.String(), vid.String(), aid.String()
	if actor != nil {
		a := actor.String()
		c.ActorID = &a
	}
	return c, err
}

// CommandInput is a validated request to ban or unban one address.
type CommandInput struct {
	Action, Jail, IP, IdempotencyKey, RequestID, ActorID string
	TTL                                                  time.Duration
}

// ErrIdempotencyMismatch means the key was used before for a different command.
var ErrIdempotencyMismatch = errors.New("store: idempotency key reused for a different command")

// CreateCommand records a command for the server's live agent. The same idempotency key with the same
// content returns the command already recorded (created=false) and sends nothing new; with different
// content it is refused. The agent is taken from the server's own row, never from the caller.
func (s *Store) CreateCommand(ctx context.Context, sc Scope, vpsID string, in CommandInput, now time.Time) (SecCommand, bool, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return SecCommand{}, false, err
	}
	vid := uuid.MustParse(vpsID)
	var aid uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT id FROM security_agents WHERE vps_id=$1 AND status <> 'revoked'`, vid).Scan(&aid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SecCommand{}, false, ErrNotFound
		}
		return SecCommand{}, false, err
	}
	var actor *uuid.UUID
	if u, err := uuid.Parse(in.ActorID); err == nil {
		actor = &u
	}
	ip := in.IP
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = a.Unmap().String()
	}
	var out SecCommand
	created := false
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		ex, err := scanCmd(tx.QueryRow(ctx, `SELECT `+cmdCols+` FROM security_commands WHERE vps_id=$1 AND idempotency_key=$2 FOR UPDATE`, vid, in.IdempotencyKey))
		if err == nil {
			if ex.Action != in.Action || ex.Jail != in.Jail || ex.IP != ip {
				return ErrIdempotencyMismatch
			}
			out = ex
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		out, err = scanCmd(tx.QueryRow(ctx, `INSERT INTO security_commands (vps_id, agent_id, action, jail, ip, actor_id, request_id, idempotency_key, requested_at, deadline)
			VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10) RETURNING `+cmdCols,
			vid, aid, in.Action, in.Jail, ip, actor, in.RequestID, in.IdempotencyKey, now, now.Add(in.TTL)))
		created = err == nil
		return err
	})
	return out, created, err
}

// MarkSent notes that the command went out on the agent's connection.
func (s *Store) MarkSent(ctx context.Context, id string, now time.Time) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE security_commands SET sent_at=$2 WHERE id=$1 AND state='pending'`, u, now)
	return err
}

// FailCommand ends a command that could not be sent. Nothing reached the agent, so this is a plain failure.
func (s *Store) FailCommand(ctx context.Context, id, code string, now time.Time) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE security_commands SET state='failed', result_code=$2, finished_at=$3 WHERE id=$1 AND state='pending'`, u, code, now)
	return err
}

// CompleteCommand stores an agent's answer. Only the agent the command was sent to can answer it, and only
// once: an answer to a command that is no longer pending is ignored (nil, ErrNotFound). An "executed" the
// agent could not verify is stored as "unknown", never as success.
func (s *Store) CompleteCommand(ctx context.Context, agentID string, r secproto.CommandResult, now time.Time) (SecCommand, error) {
	cid, err := ParseID(r.ID)
	if err != nil {
		return SecCommand{}, ErrNotFound
	}
	aid, err := ParseID(agentID)
	if err != nil {
		return SecCommand{}, ErrNotFound
	}
	state := r.Status
	switch r.Status {
	case secproto.CmdExecuted:
		if !r.Verified {
			state = "unknown"
		}
	case secproto.CmdAlreadyDone:
		if !r.Verified {
			state = "unknown"
		}
	case secproto.CmdRejected, secproto.CmdFailed, secproto.CmdExpired, secproto.CmdDuplicate:
	default:
		state = "unknown"
	}
	code := r.Code
	if len(code) > 40 {
		code = code[:40]
	}
	return scanCmd(s.pool.QueryRow(ctx, `UPDATE security_commands SET state=$3, result_code=NULLIF($4,''), verified=$5, finished_at=$6
		WHERE id=$1 AND agent_id=$2 AND state='pending' RETURNING `+cmdCols, cid, aid, state, code, r.Verified && (state == "executed" || state == "already_done"), now))
}

// GetCommand returns a command of a server the scope can see.
func (s *Store) GetCommand(ctx context.Context, sc Scope, id string) (SecCommand, error) {
	u, err := ParseID(id)
	if err != nil {
		return SecCommand{}, ErrNotFound
	}
	c, err := scanCmd(s.pool.QueryRow(ctx, `SELECT `+cmdCols+` FROM security_commands WHERE id=$1`, u))
	if err != nil {
		return SecCommand{}, err
	}
	if _, err := s.GetVPS(ctx, sc, c.VPSID); err != nil {
		return SecCommand{}, ErrNotFound
	}
	return c, nil
}

// ListCommands returns a server's recent commands, newest first.
func (s *Store) ListCommands(ctx context.Context, sc Scope, vpsID string, limit int) ([]SecCommand, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+cmdCols+` FROM security_commands WHERE vps_id=$1 ORDER BY requested_at DESC, id DESC LIMIT $2`, uuid.MustParse(vpsID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecCommand{}
	for rows.Next() {
		c, err := scanCmd(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SettleCommands does the two jobs of the sweeper. A pending command past its deadline becomes unknown (the
// answer may still be on its way, or lost). An unknown command is then compared with the state Fail2ban
// reported after it was sent: the address in the wanted state settles it as confirmed_by_state, and a state
// read well after the deadline with the address not in the wanted state ends it as failed. The wording of
// neither claims more than the state read shows.
func (s *Store) SettleCommands(ctx context.Context, now time.Time) (int, error) {
	n := 0
	tag, err := s.pool.Exec(ctx, `UPDATE security_commands SET state='unknown', result_code='no_answer', finished_at=$1 WHERE state='pending' AND deadline < $1`, now)
	if err != nil {
		return 0, err
	}
	n += int(tag.RowsAffected())

	rows, err := s.pool.Query(ctx, `SELECT `+cmdCols+` FROM security_commands WHERE state='unknown' AND finished_at > $1`, now.Add(-24*time.Hour))
	if err != nil {
		return n, err
	}
	var open []SecCommand
	for rows.Next() {
		c, err := scanCmd(rows)
		if err != nil {
			rows.Close()
			return n, err
		}
		open = append(open, c)
	}
	rows.Close()
	for _, c := range open {
		var observed time.Time
		var status string
		var data []byte
		err := s.pool.QueryRow(ctx, `SELECT status, observed_at, data FROM security_snapshot_state WHERE vps_id=$1 AND category='fail2ban'`, c.VPSID).Scan(&status, &observed, &data)
		if err != nil || status != secproto.StatusOK || c.SentAt == nil || !observed.After(*c.SentAt) {
			continue
		}
		var f secproto.Fail2ban
		if json.Unmarshal(data, &f) != nil {
			continue
		}
		banned := false
		for _, j := range f.Jails {
			if j.Name != c.Jail {
				continue
			}
			for _, e := range j.BannedIPs {
				if a, err := netip.ParseAddr(e); err == nil && a.Unmap().String() == c.IP {
					banned = true
				}
			}
		}
		next := ""
		switch {
		case banned == (c.Action == "ban"):
			next = "confirmed_by_state"
		case observed.After(c.Deadline.Add(35 * time.Second)):
			next = "failed"
		}
		if next == "" {
			continue
		}
		code := "state_read"
		if next == "failed" {
			code = "state_unchanged"
		}
		if _, err := s.pool.Exec(ctx, `UPDATE security_commands SET state=$2, result_code=$3, verified=$4 WHERE id=$1 AND state='unknown'`,
			c.ID, next, code, next == "confirmed_by_state"); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// CreateCommandLookup returns the command recorded under an idempotency key, for answering a repeat of a
// request when a new one could not be sent.
func (s *Store) CreateCommandLookup(ctx context.Context, sc Scope, vpsID, key string) (SecCommand, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return SecCommand{}, err
	}
	return scanCmd(s.pool.QueryRow(ctx, `SELECT `+cmdCols+` FROM security_commands WHERE vps_id=$1 AND idempotency_key=$2`, uuid.MustParse(vpsID), key))
}
