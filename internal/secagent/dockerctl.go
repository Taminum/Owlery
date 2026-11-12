package secagent

import (
	"context"
	"time"

	"github.com/Taminum/Owlery/internal/dockerhelper"
	"github.com/Taminum/Owlery/internal/secproto"
)

// dockerHandle answers one request through the Docker helper. The name is checked here again, whatever the server sent, and the
// agent never learns anything about Docker beyond what the helper returns.
func (a *agent) dockerHandle(ctx context.Context, req secproto.DockerReq) secproto.DockerResult {
	res := secproto.DockerResult{Type: "docker_result", ID: req.ID}
	if !a.dockerReady() {
		res.Code = "not_enabled"
		return res
	}
	if (req.Op != secproto.DockerLogs && req.Op != secproto.DockerRestart) || !dockerhelper.ValidName(req.Name) {
		res.Code = dockerhelper.CodeBadRequest
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	rs, err := dockerhelper.Client{Path: a.cfg.DockerSocket}.Do(ctx, dockerhelper.Request{Op: req.Op, Name: req.Name, Tail: min(req.Tail, secproto.MaxDockerTail)})
	if err != nil {
		res.Code = dockerhelper.CodeUnavailable
		return res
	}
	res.OK, res.Code, res.Log, res.Truncated, res.Running = rs.OK, rs.Code, rs.Log, rs.Truncated, rs.Running
	return res
}
