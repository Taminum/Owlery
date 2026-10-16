package httpapi

import (
	"errors"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

var billCurrencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

type billBody struct {
	Name         string  `json:"name"`
	Provider     string  `json:"provider"`
	Amount       float64 `json:"amount"`
	Currency     string  `json:"currency"`
	PeriodMonths int     `json:"period_months"`
	NextDue      string  `json:"next_due"`
	Note         string  `json:"note"`
}

// billOwner admits the owner only: the list of what is paid for belongs to the owner, not to a panel.
func (s *Server) billOwner(w http.ResponseWriter, r *http.Request, a auth.Actor) bool {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can see payments")
		return false
	}
	return true
}

func (s *Server) billInput(w http.ResponseWriter, r *http.Request) (store.BillInput, bool) {
	var b billBody
	if !s.decode(w, r, &b) {
		return store.BillInput{}, false
	}
	b.Name, b.Provider, b.Note = strings.TrimSpace(b.Name), strings.TrimSpace(b.Provider), strings.TrimSpace(b.Note)
	b.Currency = strings.ToUpper(strings.TrimSpace(b.Currency))
	due, err := time.Parse("2006-01-02", b.NextDue)
	switch {
	case b.Name == "" || utf8.RuneCountInString(b.Name) > 80 || utf8.RuneCountInString(b.Provider) > 80 || utf8.RuneCountInString(b.Note) > 300:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_bill", "the name is required and must be short")
	case math.IsNaN(b.Amount) || math.IsInf(b.Amount, 0) || b.Amount < 0 || b.Amount > 1e9:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_amount", "the amount must be a number from 0")
	case !billCurrencyRe.MatchString(b.Currency):
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_currency", "the currency is a three-letter code such as EUR")
	case b.PeriodMonths < 1 || b.PeriodMonths > 60:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_period", "the period is 1 to 60 months")
	case err != nil || due.Year() < 2020 || due.Year() > 2100:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_date", "the due date is a day like 2026-11-20")
	default:
		return store.BillInput{Name: b.Name, Provider: b.Provider, Amount: math.Round(b.Amount*100) / 100, Currency: b.Currency, PeriodMonths: b.PeriodMonths, NextDue: due, Note: b.Note}, true
	}
	return store.BillInput{}, false
}

func (s *Server) listBills(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.billOwner(w, r, a) {
		return
	}
	bills, err := s.Store.Bills(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	// What the active bills cost per month, by currency: a yearly bill counts as a twelfth.
	monthly := map[string]float64{}
	for _, b := range bills {
		monthly[b.Currency] += b.Amount / float64(b.PeriodMonths)
	}
	for k, v := range monthly {
		monthly[k] = math.Round(v*100) / 100
	}
	writeJSON(w, http.StatusOK, map[string]any{"bills": bills, "monthly": monthly})
}

func (s *Server) createBill(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.billOwner(w, r, a) {
		return
	}
	in, ok := s.billInput(w, r)
	if !ok {
		return
	}
	b, err := s.Store.CreateBill(r.Context(), in)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "bill.create", "bill", b.ID, map[string]any{"name": b.Name})
	writeJSON(w, http.StatusCreated, b)
}

func (s *Server) updateBill(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.billOwner(w, r, a) {
		return
	}
	in, ok := s.billInput(w, r)
	if !ok {
		return
	}
	b, err := s.Store.UpdateBill(r.Context(), r.PathValue("id"), in)
	if err != nil {
		s.billFail(w, r, err)
		return
	}
	s.audit(r, a, "", "bill.update", "bill", b.ID, map[string]any{"name": b.Name})
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) deleteBill(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.billOwner(w, r, a) {
		return
	}
	if err := s.Store.ArchiveBill(r.Context(), r.PathValue("id")); err != nil {
		s.billFail(w, r, err)
		return
	}
	s.audit(r, a, "", "bill.delete", "bill", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) payBill(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.billOwner(w, r, a) {
		return
	}
	b, err := s.Store.MarkBillPaid(r.Context(), r.PathValue("id"), time.Now().UTC().Truncate(24*time.Hour))
	if err != nil {
		s.billFail(w, r, err)
		return
	}
	s.audit(r, a, "", "bill.paid", "bill", b.ID, map[string]any{"next_due": b.NextDue})
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) billFail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such payment")
		return
	}
	s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
}
