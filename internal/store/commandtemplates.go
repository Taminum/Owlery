package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// CommandTemplate is a command kept ready for the terminal of Linux or Windows machines.
type CommandTemplate struct {
	ID        string    `json:"id"`
	OS        string    `json:"os"`
	Name      string    `json:"name"`
	Command   string    `json:"command"`
	Note      string    `json:"note"`
	Danger    bool      `json:"danger"`
	CreatedAt time.Time `json:"created_at"`
}

const (
	MaxTemplateName    = 80
	MaxTemplateCommand = 2000
	MaxTemplateNote    = 200
)

// cleanCommand keeps line breaks (a command may be several lines) and drops every other control character.
func cleanCommand(s string, n int) string {
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\r\n", "\n"), "")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}

func validTemplateOS(os string) bool { return os == "linux" || os == "windows" }

func (s *Store) ListCommandTemplates(ctx context.Context, os string) ([]CommandTemplate, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, os, name, command, note, danger, created_at FROM command_templates WHERE ($1 = '' OR os = $1) ORDER BY os, lower(name)`, os)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CommandTemplate{}
	for rows.Next() {
		var c CommandTemplate
		var id uuid.UUID
		if err := rows.Scan(&id, &c.OS, &c.Name, &c.Command, &c.Note, &c.Danger, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.ID = id.String()
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) CreateCommandTemplate(ctx context.Context, c CommandTemplate) (CommandTemplate, error) {
	c.Name, c.Command, c.Note = cleanText(c.Name, MaxTemplateName), cleanCommand(c.Command, MaxTemplateCommand), cleanText(c.Note, MaxTemplateNote)
	if c.Name == "" || c.Command == "" || !validTemplateOS(c.OS) {
		return CommandTemplate{}, errors.New("store: bad template")
	}
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `INSERT INTO command_templates (os, name, command, note, danger) VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
		c.OS, c.Name, c.Command, c.Note, c.Danger).Scan(&id, &c.CreatedAt)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return CommandTemplate{}, ErrConflict
	}
	c.ID = id.String()
	return c, err
}

// UpdateCommandTemplate changes a template's name, command, note and danger flag; its system stays.
func (s *Store) UpdateCommandTemplate(ctx context.Context, id string, c CommandTemplate) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	c.Name, c.Command, c.Note = cleanText(c.Name, MaxTemplateName), cleanCommand(c.Command, MaxTemplateCommand), cleanText(c.Note, MaxTemplateNote)
	if c.Name == "" || c.Command == "" {
		return errors.New("store: bad template")
	}
	tag, err := s.pool.Exec(ctx, `UPDATE command_templates SET name=$2, command=$3, note=$4, danger=$5 WHERE id=$1`, vid, c.Name, c.Command, c.Note, c.Danger)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrConflict
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeleteCommandTemplate(ctx context.Context, id string) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM command_templates WHERE id=$1`, vid)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
