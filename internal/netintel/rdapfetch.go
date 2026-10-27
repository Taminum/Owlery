package netintel

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/Taminum/Owlery/internal/safehttp"
)

// maxRDAPHops is how many redirects an RDAP lookup follows: rdap.org answers with a redirect to the
// registry that holds the record, and that registry may redirect once more.
const maxRDAPHops = 3

// rdapGet fetches an RDAP URL and follows its redirects by hand. Every hop must be https on the
// default port, and goes through the same guarded client as the first request, which resolves the
// host and refuses non-public addresses before connecting.
func (t *Tool) rdapGet(ctx context.Context, rawURL string) (*safehttp.Response, error) {
	next := rawURL
	for i := 0; ; i++ {
		resp, err := t.Fetch.Get(ctx, next, nil)
		var se *safehttp.Error
		if err == nil || !errors.As(err, &se) || se.Code != safehttp.CodeRedirect || se.Location == "" || i >= maxRDAPHops {
			return resp, err
		}
		base, perr := url.Parse(next)
		loc, lerr := base.Parse(se.Location)
		if perr != nil || lerr != nil || loc.Scheme != "https" || loc.User != nil || (loc.Port() != "" && loc.Port() != "443") || !strings.Contains(loc.Hostname(), ".") {
			return nil, err
		}
		next = loc.String()
	}
}
