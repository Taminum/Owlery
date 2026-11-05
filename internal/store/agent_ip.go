package store

import (
	"context"
	"net/netip"
)

// SetSecAgentRemoteIP remembers the address an agent connected from. Anything that is not an address is not kept.
func (s *Store) SetSecAgentRemoteIP(ctx context.Context, agentID, ip string) error {
	aid, err := ParseID(agentID)
	if err != nil {
		return ErrNotFound
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = a.Unmap().String()
	} else {
		ip = ""
	}
	_, err = s.pool.Exec(ctx, `UPDATE security_agents SET remote_ip=$2 WHERE id=$1 AND status <> 'revoked'`, aid, ip)
	return err
}

// AgentRemoteIPs gives, for each of the servers, the address its live agent last connected from. A server without an
// agent, or whose agent has not connected since the address began to be kept, is missing from the result.
func (s *Store) AgentRemoteIPs(ctx context.Context, vpsIDs []string) (map[string]string, error) {
	out := map[string]string{}
	if len(vpsIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT vps_id::text, remote_ip FROM security_agents
		WHERE vps_id = ANY($1::uuid[]) AND status <> 'revoked' AND remote_ip <> ''`, vpsIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, ip string
		if err := rows.Scan(&id, &ip); err != nil {
			return nil, err
		}
		out[id] = ip
	}
	return out, rows.Err()
}
