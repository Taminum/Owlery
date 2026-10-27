package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/Taminum/Owlery/internal/ingestproto"
)

// Alert kinds about the AmneziaWG containers themselves. They belong to the panel of the node.
const (
	AlertAWGDown     = "awg_down"      // the container runs but has no AmneziaWG interface: nothing connects
	AlertAWGToolsOld = "awg_tools_old" // the awg tools in the container are of another generation than the host's kernel module
)

// saveAWGContainers records what the snapshot said about each running container.
func (s *Store) saveAWGContainers(ctx context.Context, agentID uuid.UUID, cs []ingestproto.AWGContainer, now time.Time) error {
	for i, c := range cs {
		if i >= ingestproto.MaxAWGInstances {
			break
		}
		name := cleanText(c.Name, 80)
		if name == "" {
			continue
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO awg_containers (agent_id, container, tools, module, down, seen_at) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (agent_id, container) DO UPDATE SET tools=EXCLUDED.tools, module=EXCLUDED.module, down=EXCLUDED.down, seen_at=EXCLUDED.seen_at`,
			agentID, name, cleanText(c.Tools, 40), cleanText(c.Module, 40), c.Down, now); err != nil {
			return err
		}
	}
	return nil
}

// AWGContainerState is one container as last reported, with where it is.
type AWGContainerState struct {
	AgentID   string
	PanelID   string
	NodeName  string
	Container string
	Tools     string
	Module    string
	Down      bool
	SeenAt    time.Time
}

// AWGContainerStates lists the containers reported by active agents in the last hour. A container that has not
// been reported for longer is gone or its agent is silent, which has its own alert.
func (s *Store) AWGContainerStates(ctx context.Context, now time.Time) ([]AWGContainerState, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.agent_id, a.panel_id, n.name, c.container, c.tools, c.module, c.down, c.seen_at
		FROM awg_containers c JOIN agents a ON a.id = c.agent_id JOIN nodes n ON n.id = a.node_id
		WHERE a.status = 'active' AND c.seen_at > $1`, now.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AWGContainerState
	for rows.Next() {
		var st AWGContainerState
		var aid, pid uuid.UUID
		if err := rows.Scan(&aid, &pid, &st.NodeName, &st.Container, &st.Tools, &st.Module, &st.Down, &st.SeenAt); err != nil {
			return nil, err
		}
		st.AgentID, st.PanelID = aid.String(), pid.String()
		out = append(out, st)
	}
	return out, rows.Err()
}
