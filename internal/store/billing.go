package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AlertBillDue: a payment is due within days or is already overdue. It belongs to no panel.
const AlertBillDue = "bill_due"

type Bill struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Provider     string     `json:"provider"`
	Amount       float64    `json:"amount"`
	Currency     string     `json:"currency"`
	PeriodMonths int        `json:"period_months"`
	NextDue      string     `json:"next_due"` // YYYY-MM-DD
	Note         string     `json:"note"`
	LastPaidOn   *string    `json:"last_paid_on"`
	ArchivedAt   *time.Time `json:"archived_at,omitempty"`
}

// BillInput is what the owner may set. Dates are plain days: a payment is due "on the 20th", not at a moment.
type BillInput struct {
	Name         string
	Provider     string
	Amount       float64
	Currency     string
	PeriodMonths int
	NextDue      time.Time
	Note         string
}

const billCols = `b.id, b.name, b.provider, b.amount::float8, b.currency, b.period_months, to_char(b.next_due, 'YYYY-MM-DD'), b.note,
	(SELECT to_char(max(p.paid_on), 'YYYY-MM-DD') FROM bill_payments p WHERE p.bill_id = b.id), b.archived_at`

func scanBill(row pgx.Row) (Bill, error) {
	var b Bill
	var id uuid.UUID
	err := row.Scan(&id, &b.Name, &b.Provider, &b.Amount, &b.Currency, &b.PeriodMonths, &b.NextDue, &b.Note, &b.LastPaidOn, &b.ArchivedAt)
	b.ID = id.String()
	return b, err
}

// Bills lists the active bills, the ones due first.
func (s *Store) Bills(ctx context.Context) ([]Bill, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+billCols+` FROM bills b WHERE b.archived_at IS NULL ORDER BY b.next_due, b.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bill{}
	for rows.Next() {
		b, err := scanBill(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) CreateBill(ctx context.Context, in BillInput) (Bill, error) {
	return scanBill(s.pool.QueryRow(ctx, `WITH b AS (INSERT INTO bills (name, provider, amount, currency, period_months, next_due, note) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *)
		SELECT `+billCols+` FROM b`, in.Name, in.Provider, in.Amount, in.Currency, in.PeriodMonths, in.NextDue, in.Note))
}

func (s *Store) UpdateBill(ctx context.Context, id string, in BillInput) (Bill, error) {
	bid, err := ParseID(id)
	if err != nil {
		return Bill{}, ErrNotFound
	}
	b, err := scanBill(s.pool.QueryRow(ctx, `WITH b AS (UPDATE bills SET name=$2, provider=$3, amount=$4, currency=$5, period_months=$6, next_due=$7, note=$8
		WHERE id=$1 AND archived_at IS NULL RETURNING *) SELECT `+billCols+` FROM b`, bid, in.Name, in.Provider, in.Amount, in.Currency, in.PeriodMonths, in.NextDue, in.Note))
	if errors.Is(err, pgx.ErrNoRows) {
		return Bill{}, ErrNotFound
	}
	return b, err
}

// ArchiveBill removes a bill from the list. Its payments stay.
func (s *Store) ArchiveBill(ctx context.Context, id string) error {
	bid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE bills SET archived_at=now() WHERE id=$1 AND archived_at IS NULL`, bid)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// MarkBillPaid records a payment and moves the due date on by one period, counted from the date that was due
// and not from today, so that paying a day late does not shift every later date.
func (s *Store) MarkBillPaid(ctx context.Context, id string, paidOn time.Time) (Bill, error) {
	bid, err := ParseID(id)
	if err != nil {
		return Bill{}, ErrNotFound
	}
	var out Bill
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var due time.Time
		var months int
		var amount float64
		var cur string
		if err := tx.QueryRow(ctx, `SELECT next_due, period_months, amount::float8, currency FROM bills WHERE id=$1 AND archived_at IS NULL FOR UPDATE`, bid).Scan(&due, &months, &amount, &cur); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO bill_payments (bill_id, paid_on, due_was, amount, currency) VALUES ($1,$2,$3,$4,$5)`, bid, paidOn, due, amount, cur); err != nil {
			return err
		}
		b, err := scanBill(tx.QueryRow(ctx, `WITH b AS (UPDATE bills SET next_due = (next_due + make_interval(months => period_months))::date WHERE id=$1 RETURNING *)
			SELECT `+billCols+` FROM b`, bid))
		out = b
		return err
	})
	return out, err
}

// BillDueState is one bill that the alerts look at.
type BillDueState struct {
	ID       string
	Name     string
	Provider string
	Amount   float64
	Currency string
	NextDue  time.Time
}

func (s *Store) BillDueStates(ctx context.Context) ([]BillDueState, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, provider, amount::float8, currency, next_due FROM bills WHERE archived_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BillDueState
	for rows.Next() {
		var st BillDueState
		var id uuid.UUID
		if err := rows.Scan(&id, &st.Name, &st.Provider, &st.Amount, &st.Currency, &st.NextDue); err != nil {
			return nil, err
		}
		st.ID = id.String()
		out = append(out, st)
	}
	return out, rows.Err()
}
