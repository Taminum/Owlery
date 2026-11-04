package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/Taminum/Owlery/internal/secproto"
)

// Alert kinds about the containers of a machine.
const (
	AlertHostContainer     = "host_container"      // a container keeps restarting
	AlertHostContainerDown = "host_container_down" // a container that should always run has stopped
)

// DockerAlertState is the containers of one machine as its agent last listed them.
type DockerAlertState struct {
	VPSID      string
	Name       string
	Containers []secproto.DockerContainer
}

// DockerStates lists the machines whose agent has told about its containers in the last few minutes: an old list says
// nothing about now, so it raises nothing.
func (s *Store) DockerStates(ctx context.Context, now time.Time) ([]DockerAlertState, error) {
	rows, err := s.pool.Query(ctx, `SELECT v.id, v.name, st.data FROM security_vps v
		JOIN security_snapshot_state st ON st.vps_id = v.id AND st.category = 'docker'
		WHERE v.enabled AND v.archived_at IS NULL AND st.status = 'ok' AND st.received_at > $1`, now.Add(-5*time.Minute))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DockerAlertState
	for rows.Next() {
		var x DockerAlertState
		var id uuid.UUID
		var data []byte
		if err := rows.Scan(&id, &x.Name, &data); err != nil {
			return nil, err
		}
		x.VPSID = id.String()
		var d secproto.Docker
		if json.Unmarshal(data, &d) == nil {
			x.Containers = d.Containers
			out = append(out, x)
		}
	}
	return out, rows.Err()
}
