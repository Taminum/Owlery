package agent_test

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/agent"
	"github.com/Taminum/Owlery/internal/awgops"
	"github.com/Taminum/Owlery/internal/ingest"
	"github.com/Taminum/Owlery/internal/ingestproto"
	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/store/storetest"
)

const awgKey = "AAAA111111111111111111111111111111111111111="

// awgRig runs a real ingest server with a command hub and a real AWG agent whose helpers are small scripts.
func awgRig(t *testing.T, withManage bool) (*awgops.Hub, store.Agent, *store.Store) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	st := storetest.New(t)
	p, _ := st.CreatePanel(ctx, store.NewPanelID(), store.PanelInput{Name: "home", BaseURL: "https://home.example.com"}, nil)
	_, _ = st.UpsertNodes(ctx, p.ID, time.Now().UTC(), []store.NodeRecord{{RemoteUUID: "n", Name: "node-1"}})
	nodes, _ := st.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	a, err := st.CreateAgent(ctx, store.Scope{All: true}, p.ID, nodes[0].ID, "awg", "awg", "", store.HashAgentSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	hub := awgops.New()
	srv := httptest.NewServer((&ingest.Server{Store: st, Ops: hub}).Handler())
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	_ = os.WriteFile(tok, []byte(a.ID+"."+secret+"\n"), 0o600)
	snapshot := filepath.Join(dir, "snapshot.sh")
	_ = os.WriteFile(snapshot, []byte("printf 'I\tc1\tawg0\t1\tJc,S3,S4\t1791353419\nM\tc1\nP\tc1\t"+awgKey+"\t0\t5\t6\t10.8.1.2/32\nN\tc1\t"+awgKey+"\tPhone\n'\n"), 0o700)
	manage := filepath.Join(dir, "manage.sh")
	_ = os.WriteFile(manage, []byte(`case "$1" in
  add) printf 'RESULT\tok\t`+awgKey+`\t10.8.1.9\n\n[Interface]\nPrivateKey = SECRET\nAddress = 10.8.1.9/32\n[Peer]\nPublicKey = x\n' ;;
  revoke) printf 'RESULT\tok\t%s\t\n' "$3" ;;
esac
`), 0o700)
	cfg := agent.Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), TokenFile: tok, AllowInsecure: true, StateDir: filepath.Join(dir, "state"),
		Kind: agent.SourceAWG, AWGArgv: []string{sh, snapshot}, AWGEvery: time.Hour, Version: "test", SourceID: "awg-test",
		Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
	if withManage {
		cfg.AWGManage = []string{sh, manage}
	}
	c, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- agent.Run(c, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	})
	for i := 0; i < 200 && !hub.Online(a.ID); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !hub.Online(a.ID) {
		t.Fatal("the agent never connected")
	}
	return hub, a, st
}

func TestAWGAgentSendsSnapshotsAndCarriesOutManagementCommands(t *testing.T) {
	hub, a, st := awgRig(t, true)
	// the snapshot arrives, with the managed marker
	var insts []store.AWGInstanceRow
	for i := 0; i < 200; i++ {
		insts, _ = st.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
		if len(insts) == 1 && len(insts[0].Peers) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(insts) != 1 || insts[0].Mode != "managed" || insts[0].Peers[0].Label != "Phone" {
		t.Fatalf("%+v", insts)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := hub.Do(cctx, a.ID, ingestproto.AWGOp{Op: "add", Container: "c1", Name: "Pixel 8 (Mish)"})
	if err != nil || res.Status != "ok" || res.Key != awgKey || res.IP != "10.8.1.9" || !strings.Contains(res.Config, "PrivateKey = SECRET") {
		t.Fatalf("%v %+v", err, res)
	}
	res, err = hub.Do(cctx, a.ID, ingestproto.AWGOp{Op: "revoke", Container: "c1", Key: awgKey})
	if err != nil || res.Status != "ok" || res.Config != "" {
		t.Fatalf("%v %+v", err, res)
	}
	// the agent checks every field itself, whatever the server sends
	for name, op := range map[string]ingestproto.AWGOp{
		"bad_name":      {Op: "add", Container: "c1", Name: "x; rm -rf /"},
		"bad_container": {Op: "add", Container: "../etc", Name: "ok"},
		"bad_key":       {Op: "revoke", Container: "c1", Key: "short"},
		"bad_operation": {Op: "delete", Container: "c1", Name: "ok"},
	} {
		if res, err := hub.Do(cctx, a.ID, op); err != nil || res.Status != "error" || res.Code != name {
			t.Errorf("%s: %v %+v", name, err, res)
		}
	}
}

func TestAWGAgentWithoutManagementRefusesEveryCommand(t *testing.T) {
	hub, a, st := awgRig(t, false)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := hub.Do(cctx, a.ID, ingestproto.AWGOp{Op: "add", Container: "c1", Name: "Phone"})
	if err != nil || res.Status != "error" || res.Code != "management_off" {
		t.Fatalf("%v %+v", err, res)
	}
	_ = st
}
