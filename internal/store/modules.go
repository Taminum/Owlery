package store

import (
	"context"

	"github.com/google/uuid"
)

// Modules are the optional parts of the program, in the order the settings show them. The fleet, alerts and
// Telegram are the core and cannot be turned off.
var Modules = []string{"remnawave", "awg", "security", "intel", "billing", "proxmox"}

// offByDefault are the modules that need setting up first: until the owner turns one on it is off.
var offByDefault = map[string]bool{"proxmox": true}

type ModuleState struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// ModuleStates says which modules are on. A module nobody has touched is on, unless it needs setting up first.
func (s *Store) ModuleStates(ctx context.Context) ([]ModuleState, error) {
	rs, err := s.pool.Query(ctx, `SELECT id, enabled FROM app_modules`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	set := map[string]bool{}
	for rs.Next() {
		var id string
		var on bool
		if err := rs.Scan(&id, &on); err != nil {
			return nil, err
		}
		set[id] = on
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	out := make([]ModuleState, 0, len(Modules))
	for _, m := range Modules {
		on, touched := set[m]
		if !touched {
			on = !offByDefault[m]
		}
		out = append(out, ModuleState{ID: m, Enabled: on})
	}
	return out, nil
}

// ModuleOn says whether one module is on right now.
func (s *Store) ModuleOn(ctx context.Context, id string) (bool, error) {
	ms, err := s.ModuleStates(ctx)
	if err != nil {
		return false, err
	}
	for _, m := range ms {
		if m.ID == id {
			return m.Enabled, nil
		}
	}
	return false, nil
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
