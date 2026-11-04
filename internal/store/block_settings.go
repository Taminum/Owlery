package store

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/Taminum/Owlery/internal/secproto"
)

// BlockSettings is how one machine's address blocker is set up.
type BlockSettings struct {
	Mode      string   `json:"mode"`       // off | watch | block
	Threshold int      `json:"threshold"`  // failed sign-ins...
	WindowMin int      `json:"window_min"` // ...within this many minutes
	TTLHours  int      `json:"ttl_hours"`  // how long a block lasts; 0 is for good
	Whitelist []string `json:"whitelist"`  // addresses and networks that are never blocked
	Share     bool     `json:"share"`      // takes part in the list of blocks shared between machines
}

func DefaultBlockSettings() BlockSettings {
	return BlockSettings{Mode: secproto.BlockWatch, Threshold: 5, WindowMin: 10, TTLHours: 24, Whitelist: []string{}, Share: true}
}

// MaxWhitelist bounds the whitelist: it travels to the agent in one message.
const MaxWhitelist = 100

// ErrBadBlockSettings is a setting out of range or a whitelist entry that is not an address or a network.
var ErrBadBlockSettings = errors.New("store: bad block settings")

// CleanBlockSettings checks the settings and writes the whitelist in one form (a single address as /32 or /128).
func CleanBlockSettings(b BlockSettings) (BlockSettings, error) {
	if b.Mode != secproto.BlockOff && b.Mode != secproto.BlockWatch && b.Mode != secproto.BlockOn {
		return b, ErrBadBlockSettings
	}
	if b.Threshold < 2 || b.Threshold > 1000 || b.WindowMin < 1 || b.WindowMin > 1440 || b.TTLHours < 0 || b.TTLHours > 8760 || len(b.Whitelist) > MaxWhitelist {
		return b, ErrBadBlockSettings
	}
	seen := map[string]bool{}
	clean := []string{}
	for _, w := range b.Whitelist {
		var p netip.Prefix
		if pre, err := netip.ParsePrefix(w); err == nil {
			p = pre.Masked()
		} else if ip, err := netip.ParseAddr(w); err == nil {
			p = netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen())
		} else {
			return b, ErrBadBlockSettings
		}
		if s := p.String(); !seen[s] {
			seen[s] = true
			clean = append(clean, s)
		}
	}
	b.Whitelist = clean
	return b, nil
}

// GetBlockSettings returns the machine's settings, or the defaults when nobody has changed any.
func (s *Store) GetBlockSettings(ctx context.Context, vpsID string) (BlockSettings, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return BlockSettings{}, ErrNotFound
	}
	b := DefaultBlockSettings()
	err = s.pool.QueryRow(ctx, `SELECT mode, threshold, window_min, ttl_hours, whitelist, share FROM security_block_settings WHERE vps_id=$1`, vid).
		Scan(&b.Mode, &b.Threshold, &b.WindowMin, &b.TTLHours, &b.Whitelist, &b.Share)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultBlockSettings(), nil
	}
	if b.Whitelist == nil {
		b.Whitelist = []string{}
	}
	return b, err
}

// PutBlockSettings saves checked settings.
func (s *Store) PutBlockSettings(ctx context.Context, vpsID string, b BlockSettings) error {
	vid, err := ParseID(vpsID)
	if err != nil {
		return ErrNotFound
	}
	b, err = CleanBlockSettings(b)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO security_block_settings (vps_id, mode, threshold, window_min, ttl_hours, whitelist, share, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (vps_id) DO UPDATE SET mode=$2, threshold=$3, window_min=$4, ttl_hours=$5, whitelist=$6, share=$7, updated_at=now()`,
		vid, b.Mode, b.Threshold, b.WindowMin, b.TTLHours, b.Whitelist, b.Share)
	return err
}

// Message is the settings in the form the agent is told them.
func (b BlockSettings) Message() secproto.BlockCfg {
	return secproto.BlockCfg{Type: "block_cfg", Mode: b.Mode, Threshold: b.Threshold, WindowMin: b.WindowMin, TTLHours: b.TTLHours, Whitelist: b.Whitelist}
}
