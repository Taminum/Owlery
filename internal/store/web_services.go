package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WebService is a web service of a machine that Owlery opens at its own subdomain.
type WebService struct {
	ID        string    `json:"id"`
	VPSID     string    `json:"vps_id"`
	Slug      string    `json:"slug"`
	Title     string    `json:"title"`
	Port      int       `json:"port"`
	CreatedAt time.Time `json:"created_at"`
}

const webCols = `id, vps_id, slug, title, port, created_at`

func scanWeb(r pgx.Row) (WebService, error) {
	var w WebService
	var id, vid uuid.UUID
	err := r.Scan(&id, &vid, &w.Slug, &w.Title, &w.Port, &w.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, ErrNotFound
	}
	w.ID, w.VPSID = id.String(), vid.String()
	return w, err
}

func (s *Store) ListWebServices(ctx context.Context, vpsID string) ([]WebService, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return nil, ErrNotFound
	}
	rs, err := s.pool.Query(ctx, `SELECT `+webCols+` FROM web_services WHERE vps_id=$1 AND archived_at IS NULL ORDER BY lower(title)`, vid)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []WebService{}
	for rs.Next() {
		w, err := scanWeb(rs)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rs.Err()
}

// WebServiceBySlug finds a live service by its subdomain.
func (s *Store) WebServiceBySlug(ctx context.Context, slug string) (WebService, error) {
	return scanWeb(s.pool.QueryRow(ctx, `SELECT `+webCols+` FROM web_services WHERE slug=$1 AND archived_at IS NULL`, slug))
}

// CreateWebService publishes a service. A slug that was ever used, even by a removed service, is a conflict.
func (s *Store) CreateWebService(ctx context.Context, vpsID, slug, title string, port int, by string) (WebService, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return WebService{}, ErrNotFound
	}
	var cb *uuid.UUID
	if u, err := uuid.Parse(by); err == nil {
		cb = &u
	}
	w, err := scanWeb(s.pool.QueryRow(ctx, `INSERT INTO web_services (vps_id, slug, title, port, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING `+webCols, vid, slug, title, port, cb))
	if IsUniqueViolation(err) {
		return WebService{}, ErrConflict
	}
	return w, err
}

func (s *Store) ArchiveWebService(ctx context.Context, vpsID, id string) error {
	vid, err1 := ParseID(vpsID)
	wid, err2 := ParseID(id)
	if err1 != nil || err2 != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE web_services SET archived_at=now() WHERE id=$1 AND vps_id=$2 AND archived_at IS NULL`, wid, vid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
