package store

import (
	"context"

	"github.com/google/uuid"
)

// Modules are the optional parts of the program, in the order the settings show them. The fleet, alerts and
// Telegram are the core and cannot be turned off.
var Modules = []string{"remnawave", "awg", "security", "intel", "billing"}

type ModuleState struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// ModuleStates says which modules are on. A module nobody has touched is on.
func (s *Store) ModuleStates(ctx context.Context) ([]ModuleState, error) {
	rs, err := s.pool.Query(ctx, `SELECT id, enabled FROM app_modules`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	off := map[string]bool{}
	for rs.Next() {
		var id string
		var on bool
		if err := rs.Scan(&id, &on); err != nil {
			return nil, err
		}
		off[id] = !on
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	out := make([]ModuleState, 0, len(Modules))
	for _, m := range Modules {
		out = append(out, ModuleState{ID: m, Enabled: !off[m]})
	}
	return out, nil
}

func (s *Store) SetModule(ctx context.Context, id string, enabled bool, by string) error {
	var u *uuid.UUID
	if x, err := uuid.Parse(by); err == nil {
		u = &x
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO app_modules (id, enabled, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now(), updated_by = EXCLUDED.updated_by`, id, enabled, u)
	return err
}
