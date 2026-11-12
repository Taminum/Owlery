package secagent

import (
	"context"
	"time"

	"github.com/Taminum/Owlery/internal/linuxhelper"
	"github.com/Taminum/Owlery/internal/secproto"
)

// linuxHandle answers one request through the services-and-files helper. The shape of the request is checked here again,
// whatever the server sent; the agent learns nothing beyond what the helper returns, and the helper decides what is allowed.
func (a *agent) linuxHandle(ctx context.Context, req secproto.LinuxReq) secproto.LinuxResult {
	res := secproto.LinuxResult{Type: "linux_result", ID: req.ID}
	if !a.linuxReady() {
		res.Code = "not_enabled"
		return res
	}
	if !secproto.LinuxReads[req.Op] && !secproto.LinuxWrites[req.Op] {
		res.Code = linuxhelper.CodeBadRequest
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	rs, err := linuxhelper.Client{Path: a.cfg.LinuxSocket}.Do(ctx, linuxhelper.Request{Op: req.Op, Name: req.Name, Path: req.Path, Tail: min(req.Tail, secproto.MaxLinuxTail)})
	if err != nil {
		res.Code = linuxhelper.CodeUnavailable
		return res
	}
	res.OK, res.Code, res.Units, res.Dir, res.Dirs, res.Entries, res.Text, res.Truncated, res.Active = rs.OK, rs.Code, rs.Units, rs.Dir, rs.Dirs, rs.Entries, rs.Text, rs.Truncated, rs.Active
	return res
}
