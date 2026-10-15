package secagent

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/Taminum/RemnaScope/internal/seccollect"
)

// banWatch notices that the set of banned addresses changed between two full reads, so a ban is named within
// seconds instead of being found, or missed, at the next 30-second read. It asks Fail2ban for the one cheap
// listing ("fail2ban-client banned") and compares it with the previous answer; only a difference makes the
// agent read and send Fail2ban in full. It reports nothing itself.
type banWatch struct {
	prev string
	have bool
	off  bool // the listing is not available on this Fail2ban: the full read every interval is all there is
}

var tokenRe = regexp.MustCompile(`[0-9A-Fa-f:.]{3,45}|[A-Za-z0-9_.-]+`)

// canon makes the listing independent of the order Fail2ban prints it in.
func canon(out string) string {
	t := tokenRe.FindAllString(out, -1)
	slices.Sort(t)
	return strings.Join(t, " ")
}

// changed runs the listing and reports whether it differs from the last one. The first answer is the
// baseline. A Fail2ban that does not know the command, or errors, switches the watch off for the session.
func (b *banWatch) changed(ctx context.Context, r seccollect.Runner, bin string) bool {
	if b.off {
		return false
	}
	res := r.Run(ctx, bin, "banned")
	if res.Err != nil || res.ExitCode != 0 {
		b.off = true
		return false
	}
	cur := canon(res.Stdout)
	if !b.have {
		b.prev, b.have = cur, true
		return false
	}
	if cur == b.prev {
		return false
	}
	b.prev = cur
	return true
}
