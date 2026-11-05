package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/selfupdate"
	"github.com/Taminum/Owlery/internal/store"
)

// latestRelease is the newest release of the project, asked of GitHub at most once in ten minutes. A test or a closed network
// replaces it with Server.LatestRelease.
type latestCache struct {
	mu  sync.Mutex
	tag string
	at  time.Time
}

func (s *Server) latestRelease(ctx context.Context) (string, error) {
	if s.LatestRelease != nil {
		return s.LatestRelease(ctx)
	}
	c := &s.latest
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tag != "" && time.Since(c.at) < 10*time.Minute {
		return c.tag, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/Taminum/Owlery/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "owlery")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return c.tag, errors.Join(errors.New("github did not answer"), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.tag, fmt.Errorf("github answered %d", resp.StatusCode)
	}
	var out struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || !selfupdate.ValidVersion(out.Tag) {
		return c.tag, errors.New("github gave no release version")
	}
	c.tag, c.at = out.Tag, time.Now()
	return c.tag, nil
}

// agentLatest says which release is the newest, so the card can offer an update when its agent is older.
func (s *Server) agentLatest(w http.ResponseWriter, r *http.Request, _ auth.Actor, _ store.Session) {
	tag, err := s.latestRelease(r.Context())
	if err != nil && tag == "" {
		s.writeErr(w, r, http.StatusBadGateway, "no_release_info", "the newest release could not be looked up")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"version": tag})
}

// updateAgent asks a machine's agent to update itself. Only the owner and administrators of a linked panel may, only on a machine
// whose agent says it allows it, and only to a release version that is later than the agent's own: the agent checks all of that
// again, and the release signature, on its side.
func (s *Server) updateAgent(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	var in struct {
		Version string `json:"version"` // a release tag, or empty for the newest
	}
	if !s.decode(w, r, &in) {
		return
	}
	agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return
	}
	if !slices.Contains(agent.Capabilities, secproto.CapSelfUpdate) {
		s.writeErr(w, r, http.StatusConflict, "update_not_allowed", "this machine does not allow updates from Owlery")
		return
	}
	version := in.Version
	if version == "" || version == "latest" {
		if version, err = s.latestRelease(r.Context()); err != nil || version == "" {
			s.writeErr(w, r, http.StatusBadGateway, "no_release_info", "the newest release could not be looked up")
			return
		}
	}
	if !selfupdate.ValidVersion(version) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_version", "that is not a release version")
		return
	}
	current := ""
	if agent.AgentVersion != nil {
		current = *agent.AgentVersion
	}
	if !selfupdate.Newer(version, current) {
		s.writeErr(w, r, http.StatusConflict, "up_to_date", "the agent is not older than that release")
		return
	}
	s.audit(r, a, "", "security.agent.update", "vps", v.ID, map[string]any{"name": v.Name, "from": current, "to": version})
	// The agent answers once it has fetched and checked the release, which takes a little while: past the time this request may
	// take it is "on its way", and the card watches the agent's version instead.
	ctx, cancel := context.WithTimeout(r.Context(), 70*time.Second)
	defer cancel()
	res, err := s.SecOps.Update(ctx, agent.ID, secproto.UpdateReq{Version: version})
	switch {
	case err != nil && ctx.Err() != nil:
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending", "version": version})
	case err != nil:
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
	case !res.OK && res.Error == "busy":
		// The agent is already fetching a release for an earlier request (a slow road to GitHub can take minutes): that is
		// the same update on its way, not a failure.
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending", "version": version})
	case !res.OK:
		// The agent's own explanation is written for the administrator and is shown as it is.
		s.writeErr(w, r, http.StatusConflict, "update_failed", res.Error)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"status": "started", "version": version})
	}
}
