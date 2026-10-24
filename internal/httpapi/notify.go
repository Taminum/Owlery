package httpapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/notify"
	"github.com/Taminum/RemnaScope/internal/store"
)

var (
	tgTokenRe = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,60}$`)
	tgChatRe  = regexp.MustCompile(`^-?[0-9]{3,20}$`)
)

func (s *Server) notifyOwner(w http.ResponseWriter, r *http.Request, a auth.Actor) bool {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage notifications")
		return false
	}
	if s.Ring == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "unavailable", "notifications need the master key")
		return false
	}
	return true
}

// notifyFailure turns a send error into a fixed word: Telegram's own text can echo what was sent.
func (s *Server) notifyFailure(w http.ResponseWriter, r *http.Request, err error) {
	code := notify.ErrNetwork
	var se notify.SendError
	if errors.As(err, &se) {
		code = se.Code
	}
	status := http.StatusBadGateway
	if code == notify.ErrRejected {
		status = http.StatusUnprocessableEntity
	}
	s.writeErr(w, r, status, "telegram_"+code, "Telegram did not accept it")
}

func (s *Server) notifyList(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage notifications")
		return
	}
	cs, err := s.Store.ListNotifyChannels(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": cs, "max": store.MaxNotifyChannels, "groups": store.AlertGroups, "critical": criticalList()})
}

// notifyDiscover checks a bot token and lists the chats that wrote to the bot. The token is used for these
// two calls and is not kept.
func (s *Server) notifyDiscover(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.notifyOwner(w, r, a) {
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	in.Token = strings.TrimSpace(in.Token)
	if !tgTokenRe.MatchString(in.Token) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_token", "that does not look like a bot token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	bot, chats, err := notify.Discover(ctx, in.Token)
	if err != nil {
		s.notifyFailure(w, r, err)
		return
	}
	if chats == nil {
		chats = []notify.Chat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"bot": bot, "chats": chats})
}

func (s *Server) notifyCreate(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.notifyOwner(w, r, a) {
		return
	}
	var in struct {
		Name       string `json:"name"`
		Token      string `json:"token"`
		ChatID     string `json:"chat_id"`
		OnAlerts   *bool  `json:"on_alerts"`
		DigestHour *int   `json:"digest_hour"`
		DigestTZ   string `json:"digest_tz"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	in.Name, in.Token, in.ChatID = strings.TrimSpace(in.Name), strings.TrimSpace(in.Token), strings.TrimSpace(in.ChatID)
	if in.Name == "" || len([]rune(in.Name)) > 64 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "the name must be 1 to 64 characters")
		return
	}
	if !tgTokenRe.MatchString(in.Token) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_token", "that does not look like a bot token")
		return
	}
	if !tgChatRe.MatchString(in.ChatID) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_chat", "the chat id is a number")
		return
	}
	if in.DigestHour != nil && (*in.DigestHour < 0 || *in.DigestHour > 23) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_hour", "the hour is 0 to 23")
		return
	}
	tz := in.DigestTZ
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil || len(tz) > 64 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_timezone", "unknown time zone")
		return
	}
	// It is only stored if a message actually reaches the chat.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := notify.Send(ctx, in.Token, in.ChatID, "RemnaScope: уведомления подключены. Сюда будут приходить оповещения и сводка."); err != nil {
		s.notifyFailure(w, r, err)
		return
	}
	sealed, err := notify.Seal(s.Ring, notify.Secret{Token: in.Token, ChatID: in.ChatID})
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	on := true
	if in.OnAlerts != nil {
		on = *in.OnAlerts
	}
	ch, err := s.Store.CreateNotifyChannel(r.Context(), in.Name, notify.Hint(in.ChatID), sealed, on, in.DigestHour, tz)
	if errors.Is(err, store.ErrLimit) {
		s.writeErr(w, r, http.StatusConflict, "limit", "too many channels")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	_ = s.Store.NotifyResult(r.Context(), ch.ID, true, "")
	s.audit(r, a, "", "notify.channel.create", "notify_channel", ch.ID, map[string]any{"kind": "telegram", "name": in.Name})
	writeJSON(w, http.StatusCreated, ch)
}

func (s *Server) notifyPatch(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage notifications")
		return
	}
	var raw map[string]any
	if !s.decode(w, r, &raw) {
		return
	}
	var p store.NotifyPatch
	if v, ok := raw["enabled"].(bool); ok {
		p.Enabled = &v
	}
	if v, ok := raw["on_alerts"].(bool); ok {
		p.OnAlerts = &v
	}
	if v, ok := raw["digest_hour"]; ok {
		p.SetDigest = true
		if f, isNum := v.(float64); isNum {
			if f < 0 || f > 23 || f != float64(int(f)) {
				s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_hour", "the hour is 0 to 23")
				return
			}
			h := int(f)
			p.DigestHour = &h
		} else if v != nil {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_hour", "the hour is 0 to 23")
			return
		}
	}
	if v, ok := raw["digest_tz"].(string); ok {
		if _, err := time.LoadLocation(v); err != nil || len(v) > 64 || v == "" {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_timezone", "unknown time zone")
			return
		}
		p.DigestTZ = &v
	}
	if v, ok := raw["commands"].(bool); ok {
		p.Commands = &v
	}
	if v, ok := raw["prefs"]; ok {
		pr, ok := parsePrefs(v)
		if !ok {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_prefs", "the notification settings are not valid")
			return
		}
		p.Prefs = &pr
	}
	if v, ok := raw["mute_hours"]; ok {
		f, isNum := v.(float64)
		if !isNum || f < 0 || f > 24*14 || f != float64(int(f)) {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_mute", "mute for 0 to 336 hours")
			return
		}
		p.SetMute = true
		if f > 0 {
			until := time.Now().UTC().Add(time.Duration(f) * time.Hour)
			p.MutedUntil = &until
		}
	}
	ch, err := s.Store.PatchNotifyChannel(r.Context(), r.PathValue("id"), p)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such channel")
		return
	}
	s.audit(r, a, "", "notify.channel.update", "notify_channel", ch.ID, nil)
	writeJSON(w, http.StatusOK, ch)
}

func (s *Server) notifyDelete(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage notifications")
		return
	}
	if err := s.Store.DeleteNotifyChannel(r.Context(), r.PathValue("id")); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such channel")
		return
	}
	s.audit(r, a, "", "notify.channel.delete", "notify_channel", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

// notifyTest sends one message to a stored channel.
func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.notifyOwner(w, r, a) {
		return
	}
	id := r.PathValue("id")
	cs, err := s.Store.ListNotifyChannels(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	var ch *store.NotifyChannel
	for i := range cs {
		if cs[i].ID == id {
			ch = &cs[i]
		}
	}
	if ch == nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such channel")
		return
	}
	wk := &notify.Worker{Store: s.Store, Ring: s.Ring, Log: s.Log}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := wk.SendTo(ctx, *ch, "RemnaScope: проверка уведомлений. Если вы это видите, всё работает."); err != nil {
		s.notifyFailure(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func criticalList() []string {
	var out []string
	for _, g := range store.AlertGroups {
		for _, k := range g.Kinds {
			if store.CriticalKinds[k] {
				out = append(out, k)
			}
		}
	}
	return out
}

var hhmm = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// parsePrefs reads the notification settings of a request and refuses anything it does not know.
func parsePrefs(v any) (store.NotifyPrefs, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return store.NotifyPrefs{}, false
	}
	var p store.NotifyPrefs
	for k, val := range m {
		switch k {
		case "off":
			arr, ok := val.([]any)
			if !ok || len(arr) > len(store.AlertGroups) {
				return p, false
			}
			seen := map[string]bool{}
			for _, x := range arr {
				id, ok := x.(string)
				if !ok || !store.ValidAlertGroup(id) {
					return p, false
				}
				if !seen[id] {
					seen[id] = true
					p.Off = append(p.Off, id)
				}
			}
		case "no_resolved":
			b, ok := val.(bool)
			if !ok {
				return p, false
			}
			p.NoResolved = b
		case "quiet_on":
			b, ok := val.(bool)
			if !ok {
				return p, false
			}
			p.QuietOn = b
		case "quiet_from", "quiet_to":
			s, ok := val.(string)
			if !ok || (s != "" && !hhmm.MatchString(s)) {
				return p, false
			}
			if k == "quiet_from" {
				p.QuietFrom = s
			} else {
				p.QuietTo = s
			}
		case "remind_hours":
			f, ok := val.(float64)
			if !ok || f < 0 || f > 168 || f != float64(int(f)) {
				return p, false
			}
			p.RemindHours = int(f)
		default:
			return p, false
		}
	}
	if p.QuietOn && (p.QuietFrom == "" || p.QuietTo == "" || p.QuietFrom == p.QuietTo) {
		return p, false
	}
	return p, true
}
