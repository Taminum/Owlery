//go:build linux

package awgsensor

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// OpenCapture opens a packet socket on an interface that lives in another process's network namespace
// (a container's) and returns it. The socket stays attached to that namespace after the calling thread
// has gone back to its own, so nothing else in this process is affected.
func OpenCapture(pid int, iface string) (int, error) {
	runtime.LockOSThread()
	restored := false
	defer func() {
		if restored { // a thread that could not go back must never be handed to other work
			runtime.UnlockOSThread()
		}
	}()
	self, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("opening the current namespace: %w", err)
	}
	defer unix.Close(self)
	target, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		restored = true
		return -1, fmt.Errorf("opening the container's namespace: %w", err)
	}
	defer unix.Close(target)
	if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
		restored = true
		return -1, fmt.Errorf("entering the container's namespace: %w", err)
	}
	fd, serr := openPacketSocket(iface)
	if err := unix.Setns(self, unix.CLONE_NEWNET); err != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		return -1, errors.New("could not return to the host namespace") // the thread stays locked and is discarded
	}
	restored = true
	return fd, serr
}

func openPacketSocket(iface string) (int, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return -1, fmt.Errorf("no interface %s in the container: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	tv := unix.NsecToTimeval(int64(time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return fd, nil
}

// DropPrivileges gives up root for good. Call it once the socket is open: reading it needs nothing more.
func DropPrivileges() error {
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(65534); err != nil {
		return err
	}
	if err := syscall.Setuid(65534); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

// Read takes packets from the socket and feeds them to the aggregator until stop is closed. emit is called
// with each finished window every interval.
func Read(fd int, a *Aggregator, interval time.Duration, emit func(start, end time.Time, flows []Flow, dropped uint64), stop <-chan struct{}) error {
	buf := make([]byte, 65536)
	windowStart := time.Now()
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, from, err := unix.Recvfrom(fd, buf, 0)
		now := time.Now()
		switch {
		case err == nil && n > 0:
			dir := FromClient
			if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
				dir = ToClient
			}
			a.Add(dir, buf[:n], now)
		case err == nil, errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
		default:
			return err
		}
		if now.Sub(windowStart) >= interval {
			dropped := a.Dropped
			emit(windowStart, now, a.Flush(now), dropped)
			windowStart = now
		}
	}
}
