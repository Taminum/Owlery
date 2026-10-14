package keyrotate

import (
	"bytes"
	"context"
	"testing"

	"github.com/Taminum/RemnaScope/internal/secrets"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
)

var ctx = context.Background()

func ring(t *testing.T, active int, versions ...int) *secrets.Keyring {
	keys := map[int][]byte{}
	for _, v := range versions {
		keys[v] = bytes.Repeat([]byte{byte(v)}, 32)
	}
	r, err := secrets.NewKeyring(keys, active)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mk(t *testing.T, st *store.Store, r *secrets.Keyring, name, token string) string {
	id := store.NewPanelID()
	sl, _ := r.Seal(id, []byte(token))
	if _, err := st.CreatePanel(ctx, id, store.PanelInput{Name: name, BaseURL: "https://" + name + ".example.com"}, &sl); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRotationMovesEverythingToTheActiveKey(t *testing.T) {
	st := storetest.New(t)
	old := ring(t, 1, 1)
	a, b := mk(t, st, old, "a", "token-a"), mk(t, st, old, "b", "token-b")

	both := ring(t, 2, 1, 2)
	res, err := Run(ctx, st, both)
	if err != nil || res.Rotated != 2 || res.Current != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	for id, want := range map[string]string{a: "token-a", b: "token-b"} {
		sl, _ := st.Credential(ctx, id)
		if sl.KeyVersion != 2 {
			t.Fatalf("panel %s still on v%d", id, sl.KeyVersion)
		}
		// The retired key is no longer needed.
		pt, err := ring(t, 2, 2).Open(id, sl)
		if err != nil || string(pt) != want {
			t.Fatalf("%q %v", pt, err)
		}
	}
	if res, _ := Run(ctx, st, both); res.Rotated != 0 || res.Current != 2 {
		t.Fatalf("second run must be a no-op: %+v", res)
	}
}

func TestRotationFailsLoudlyWhenAnOldKeyIsMissing(t *testing.T) {
	st := storetest.New(t)
	id := mk(t, st, ring(t, 1, 1), "a", "token-a")
	before, _ := st.Credential(ctx, id)

	if _, err := Run(ctx, st, ring(t, 3, 3)); err == nil {
		t.Fatal("rotating without the key that encrypted the data must fail")
	}
	after, _ := st.Credential(ctx, id)
	if !bytes.Equal(before.Ciphertext, after.Ciphertext) || before.KeyVersion != after.KeyVersion {
		t.Fatal("a failed rotation must leave the credential untouched")
	}
}
