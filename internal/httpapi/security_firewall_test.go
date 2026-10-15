package httpapi

import (
	"encoding/json"
	"testing"
	"time"
)

func addFW(t *testing.T, w *world, vps, status, hash, rules string, at time.Time) {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"backend": "nft", "rules": rules})
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_snapshots (vps_id, category, status, source_hash, observed_at, received_at, data)
		VALUES ($1,'firewall',$2,$3,$4,$4,$5::jsonb)`, vps, status, hash, at, string(data)); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallHistoryAndDiff(t *testing.T) {
	w := newAgentWorld(t)
	v := mkVPS(t, w, "Fw", "203.0.113.20", w.work.ID)
	hidden := mkVPS(t, w, "Private", "203.0.113.21", "")
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	const one = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}"
	const two = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t\ttcp dport 8080 accept\n\t}\n}"

	type diffResp struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
		Added     int    `json:"added"`
		Removed   int    `json:"removed"`
		Lines     []struct {
			Op   string `json:"op"`
			Text string `json:"text"`
		} `json:"lines"`
		From struct {
			ID string `json:"id"`
		} `json:"from"`
	}
	path := "/api/v1/security/vps/" + v + "/firewall/diff"
	_, b := w.owner.get(path)
	if d := parse[diffResp](t, b); d.Available || d.Reason != "fewer_than_two_readings" {
		t.Fatalf("with no readings there is nothing to compare: %s", b)
	}

	addFW(t, w, v, "ok", "h1", one, t0)
	addFW(t, w, v, "error", "h2", "", t0.Add(time.Minute)) // an incomplete reading is skipped, never compared
	addFW(t, w, v, "ok", "h3", two, t0.Add(2*time.Minute))

	_, b = w.owner.get(path)
	d := parse[diffResp](t, b)
	if !d.Available || d.Added != 1 || d.Removed != 0 {
		t.Fatalf("%s", b)
	}
	var plus string
	for _, l := range d.Lines {
		if l.Op == "+" {
			plus = l.Text
		}
	}
	if plus != "\t\ttcp dport 8080 accept" {
		t.Fatalf("added line: %q", plus)
	}

	// Explicit ids work, and a reading of another server's cannot be asked for through this one.
	_, hb := w.owner.get("/api/v1/security/vps/" + v + "/firewall/history")
	var hist struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(hb, &hist); err != nil || len(hist.Items) != 3 || hist.Items[0].Status != "ok" {
		t.Fatalf("%s", hb)
	}
	if string(hb) != "" && containsRules(hb) {
		t.Fatalf("the history must not carry rule text: %s", hb)
	}
	newest, oldest := hist.Items[0].ID, hist.Items[2].ID
	_, b = w.owner.get(path + "?from=" + oldest + "&to=" + newest)
	if d := parse[diffResp](t, b); !d.Available || d.From.ID != oldest || d.Added != 1 {
		t.Fatalf("%s", b)
	}
	_, b = w.owner.get(path + "?from=" + oldest + "&to=" + hist.Items[1].ID)
	if d := parse[diffResp](t, b); d.Available || d.Reason != "a_reading_was_incomplete" {
		t.Fatalf("%s", b)
	}

	// A panel role does not see a private server, nor its history.
	if st, _ := w.viewer.get("/api/v1/security/vps/" + hidden + "/firewall/diff"); st != 404 {
		t.Fatalf("private server answered %d", st)
	}
	if st, _ := w.viewer.get("/api/v1/security/vps/" + v + "/firewall/history?limit=0"); st != 400 {
		t.Fatalf("limit=0 answered %d", st)
	}
}

func containsRules(b []byte) bool {
	var m struct {
		Items []map[string]any `json:"items"`
	}
	if json.Unmarshal(b, &m) != nil {
		return true
	}
	for _, it := range m.Items {
		if _, ok := it["rules"]; ok {
			return true
		}
	}
	return false
}
