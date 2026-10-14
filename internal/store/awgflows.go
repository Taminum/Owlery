package store

import (
	"context"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/geoip"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/site"
)

var flowNameRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9._-]{0,251}[a-z0-9_])?$`)

const maxFlowBytes = uint64(1) << 50 // anything larger in one minute is a corrupt report

// SaveAWGFlows adds one reporting window of one container to the hourly sums. Entries that are not what they
// should be are skipped; the window is never an error for the agent.
func (s *Store) SaveAWGFlows(ctx context.Context, agent Agent, fr ingestproto.AWGFlows, now time.Time) error {
	cont := cleanText(fr.Container, 80)
	var instID string
	err := s.pool.QueryRow(ctx, `SELECT id::text FROM awg_instances WHERE agent_id=$1 AND container=$2 ORDER BY interface LIMIT 1`, agent.ID, cont).Scan(&instID)
	if err != nil {
		return nil // no snapshot has announced this container yet: the next windows will be kept
	}
	// device addresses -> peers
	peers := map[string]string{}
	rs, err := s.pool.Query(ctx, `SELECT split_part(tunnel_ip,'/',1), id::text FROM awg_peers WHERE instance_id=$1 AND tunnel_ip <> '' AND gone_at IS NULL`, instID)
	if err != nil {
		return err
	}
	for rs.Next() {
		var ip, id string
		if err := rs.Scan(&ip, &id); err != nil {
			rs.Close()
			return err
		}
		peers[ip] = id
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return err
	}
	// The window is credited to the hour in which it ended (a window is a minute: crossing an hour is rare and harmless).
	end := time.Unix(fr.End, 0).UTC()
	if fr.End <= 0 || end.After(now.Add(5*time.Minute)) || end.Before(now.Add(-48*time.Hour)) {
		end = now.UTC()
	}
	hour := end.Truncate(time.Hour)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for i, f := range fr.Flows {
		if i >= ingestproto.MaxAWGFlows {
			break
		}
		client, e1 := netip.ParseAddr(f.Client)
		remote, e2 := netip.ParseAddr(f.Remote)
		if e1 != nil || e2 != nil || (f.Proto != 1 && f.Proto != 6 && f.Proto != 17) || f.Up > maxFlowBytes || f.Down > maxFlowBytes || f.Up+f.Down == 0 {
			continue
		}
		name, src := strings.ToLower(f.Name), f.How
		if name != "" && (!flowNameRe.MatchString(name) || (src != "sni" && src != "host" && src != "dns")) {
			name, src = "", ""
		}
		if name == "" {
			src = ""
		}
		var siteOf, countryOf any
		if name != "" {
			if st := site.Of(name); st != "" {
				siteOf = st
			}
		}
		if cc := geoip.Default().Country(remote); cc != "" {
			countryOf = cc
		}
		var peer any
		if id, ok := peers[client.Unmap().String()]; ok {
			peer = id
		}
		if _, err := tx.Exec(ctx, `INSERT INTO awg_flow_hourly (instance_id, peer_id, client_ip, hour, proto, remote_ip, remote_port, name, name_src, up_bytes, down_bytes, last_seen, site, country, flows)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT (instance_id, client_ip, hour, proto, remote_ip, remote_port, name)
			DO UPDATE SET up_bytes=awg_flow_hourly.up_bytes+EXCLUDED.up_bytes, down_bytes=awg_flow_hourly.down_bytes+EXCLUDED.down_bytes, flows=awg_flow_hourly.flows+EXCLUDED.flows,
			  site=COALESCE(awg_flow_hourly.site, EXCLUDED.site), country=COALESCE(awg_flow_hourly.country, EXCLUDED.country),
			  last_seen=GREATEST(awg_flow_hourly.last_seen, EXCLUDED.last_seen), peer_id=COALESCE(EXCLUDED.peer_id, awg_flow_hourly.peer_id)`,
			instID, peer, client.Unmap().String(), hour, int16(f.Proto), remote.Unmap().String(), int(f.Port), name, src, int64(f.Up), int64(f.Down), end, siteOf, countryOf, int(min(f.New, 1))); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// PruneAWGFlows removes sums older than the given age. Returns how many rows went.
func (s *Store) PruneAWGFlows(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM awg_flow_hourly WHERE hour < now() - make_interval(secs => $1)`, olderThan.Seconds())
	return tag.RowsAffected(), err
}
