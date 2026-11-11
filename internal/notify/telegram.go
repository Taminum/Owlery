// Package notify sends what Owlery wants the owner to know to Telegram: alerts as they open and close,
// and a short daily digest. It is outbound only, to one fixed host, and it never puts a token in a log, an
// error or a response.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// BaseURL is Telegram's Bot API. Tests point it at a local server.
var BaseURL = "https://api.telegram.org"

// Failure codes: the only things that are ever stored or shown about a failed send.
const (
	ErrNetwork   = "network"
	ErrRejected  = "rejected" // Telegram answered, and said no (a wrong token, a chat that did not start the bot)
	ErrBadAnswer = "bad_answer"
)

var ErrSend = errors.New("notify: send failed")

type SendError struct{ Code string }

func (e SendError) Error() string { return "notify: " + e.Code }

func client() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		// A redirect from Telegram's API is not expected; following one could carry the token to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type apiResp struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
}

func call(ctx context.Context, token, method string, body any) (apiResp, error) {
	var rd io.Reader
	verb := http.MethodGet
	if body != nil {
		b, _ := json.Marshal(body)
		rd, verb = bytes.NewReader(b), http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, verb, BaseURL+"/bot"+token+"/"+method, rd)
	if err != nil {
		return apiResp{}, SendError{ErrNetwork}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client().Do(req)
	if err != nil {
		return apiResp{}, SendError{ErrNetwork} // the error text can carry the URL, which holds the token
	}
	defer res.Body.Close()
	var out apiResp
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return apiResp{}, SendError{ErrBadAnswer}
	}
	if !out.OK {
		return out, SendError{ErrRejected}
	}
	return out, nil
}

// Send posts one plain-text message. Telegram's limit is 4096 characters; longer text is cut.
func Send(ctx context.Context, token, chatID, text string) error {
	r := []rune(text)
	if len(r) > 4000 {
		text = string(r[:4000]) + "…"
	}
	_, err := call(ctx, token, "sendMessage", map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true})
	return err
}

// Button is one inline button under a message. Data comes back as a press (at most 64 bytes).
type Button struct{ Text, Data string }

// SendButtons posts a message with one row of inline buttons.
func SendButtons(ctx context.Context, token, chatID, text string, row []Button) error {
	r := []rune(text)
	if len(r) > 4000 {
		text = string(r[:4000]) + "…"
	}
	kb := make([]map[string]string, 0, len(row))
	for _, b := range row {
		kb = append(kb, map[string]string{"text": b.Text, "callback_data": b.Data})
	}
	_, err := call(ctx, token, "sendMessage", map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true,
		"reply_markup": map[string]any{"inline_keyboard": [][]map[string]string{kb}}})
	return err
}

// AnswerPress tells Telegram a press was received and shows a short note to whoever pressed.
func AnswerPress(ctx context.Context, token, pressID, note string) {
	_, _ = call(ctx, token, "answerCallbackQuery", map[string]any{"callback_query_id": pressID, "text": note})
}

// ClearButtons takes the buttons off a message once they have been used.
func ClearButtons(ctx context.Context, token, chatID string, messageID int64) {
	_, _ = call(ctx, token, "editMessageReplyMarkup", map[string]any{"chat_id": chatID, "message_id": messageID, "reply_markup": map[string]any{"inline_keyboard": [][]map[string]string{}}})
}

// Chat is a conversation that wrote to the bot.
type Chat struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Discover confirms the token and lists the chats that have written to the bot, newest first, so the owner
// can pick theirs after pressing Start in the bot.
func Discover(ctx context.Context, token string) (bot string, chats []Chat, err error) {
	me, err := call(ctx, token, "getMe", nil)
	if err != nil {
		return "", nil, err
	}
	var who struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(me.Result, &who)
	up, err := call(ctx, token, "getUpdates?limit=50", nil)
	if err != nil {
		return who.Username, nil, err
	}
	var updates []struct {
		Message *struct {
			Chat struct {
				ID        int64  `json:"id"`
				Type      string `json:"type"`
				Title     string `json:"title"`
				FirstName string `json:"first_name"`
				Username  string `json:"username"`
			} `json:"chat"`
		} `json:"message"`
	}
	if err := json.Unmarshal(up.Result, &updates); err != nil {
		return who.Username, nil, SendError{ErrBadAnswer}
	}
	seen := map[int64]bool{}
	for i := len(updates) - 1; i >= 0; i-- {
		m := updates[i].Message
		if m == nil || seen[m.Chat.ID] {
			continue
		}
		seen[m.Chat.ID] = true
		title := m.Chat.Title
		if title == "" {
			title = m.Chat.FirstName
		}
		if m.Chat.Username != "" {
			title += " (@" + m.Chat.Username + ")"
		}
		chats = append(chats, Chat{ID: strconv.FormatInt(m.Chat.ID, 10), Title: title})
	}
	return who.Username, chats, nil
}

// Hint is the last four characters of a chat id, enough to tell channels apart on the screen.
func Hint(chatID string) string {
	if len(chatID) <= 4 {
		return chatID
	}
	return fmt.Sprintf("…%s", chatID[len(chatID)-4:])
}

// Update is one message the bot received.
type Update struct {
	ID      int64
	ChatID  string
	Date    int64
	Text    string
	HasText bool
	// A press of an inline button: its id, its data and the message it was under.
	PressID   string
	PressData string
	MessageID int64
}

// Updates asks Telegram for what was written to the bot after offset, waiting up to waitSec seconds for something
// to arrive. An offset of -1 gives only the newest update. Only text messages are returned.
func Updates(ctx context.Context, token string, offset int64, waitSec int) ([]Update, int64, error) {
	r, err := call(ctx, token, "getUpdates", map[string]any{"offset": offset, "timeout": waitSec, "limit": 20, "allowed_updates": []string{"message", "callback_query"}})
	if err != nil {
		return nil, 0, err
	}
	var raw []struct {
		ID      int64 `json:"update_id"`
		Message *struct {
			Date int64  `json:"date"`
			Text string `json:"text"`
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
		Press *struct {
			ID      string `json:"id"`
			Data    string `json:"data"`
			Message *struct {
				ID   int64 `json:"message_id"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"callback_query"`
	}
	if err := json.Unmarshal(r.Result, &raw); err != nil {
		return nil, 0, SendError{ErrBadAnswer}
	}
	var out []Update
	var last int64
	for _, u := range raw {
		if u.ID > last {
			last = u.ID
		}
		if u.Press != nil && u.Press.Message != nil {
			out = append(out, Update{ID: u.ID, ChatID: strconv.FormatInt(u.Press.Message.Chat.ID, 10), PressID: u.Press.ID, PressData: u.Press.Data, MessageID: u.Press.Message.ID})
			continue
		}
		if u.Message == nil {
			continue
		}
		out = append(out, Update{ID: u.ID, ChatID: strconv.FormatInt(u.Message.Chat.ID, 10), Date: u.Message.Date, Text: u.Message.Text, HasText: u.Message.Text != ""})
	}
	return out, last, nil
}
