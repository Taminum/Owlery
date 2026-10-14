package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

// State is what an agent must remember across restarts. It is small and rewritten atomically.
type State struct {
	Epoch   string `json:"epoch"`
	NextSeq int64  `json:"next_seq"`
	// File-source checkpoint: the position in the log already turned into spool records.
	Path     string `json:"path,omitempty"`
	Offset   int64  `json:"offset,omitempty"`
	HeadHash string `json:"head_hash,omitempty"` // hash of the file's first bytes: tells "same file" from "rotated"

	// Loss not yet reported to the server. Kept on disk so a restart cannot forget it.
	PendingDropped int64             `json:"pending_dropped,omitempty"`
	PendingGaps    []ingestproto.Gap `json:"pending_gaps,omitempty"`
}

func newEpoch() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LoadState reads state.json from dir. fresh is true when there was none (a new agent or lost
// state): the epoch is new, so the server will not confuse the numbering with an earlier one.
func LoadState(dir string) (st State, fresh bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return st, false, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return State{Epoch: newEpoch(), NextSeq: 1}, true, nil
	}
	if err != nil {
		return st, false, err
	}
	if json.Unmarshal(b, &st) != nil || st.Epoch == "" || st.NextSeq < 1 {
		// A damaged file is treated like a lost one rather than trusted.
		return State{Epoch: newEpoch(), NextSeq: 1}, true, nil
	}
	return st, false, nil
}

// Save writes atomically: a crash leaves either the old or the new file, never half of one.
func (st State) Save(dir string) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "state.json.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}
