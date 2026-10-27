//go:build linux

package seccollect

import (
	"syscall"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func (h *HostReader) readOS(now time.Time) secproto.Host { return h.readProcfs(now) }

// diskUsage is the size of a file system and what is used of it, counted as df does: blocks the file system keeps
// for itself are in the total and count as used.
func diskUsage(path string) (total, used int64, err error) {
	var st syscall.Statfs_t
	if err = syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := int64(st.Bsize)
	total = int64(st.Blocks) * bs
	used = total - int64(st.Bfree)*bs
	return total, used, nil
}
