//go:build linux

package netintel

import (
	"context"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const traceSupported = true

// probeTTL sends one ICMP echo with a limited TTL on an unprivileged ICMP datagram socket and waits
// for either the echo reply (the destination) or the "time exceeded" error that the kernel queues
// on the socket when IP_RECVERR is on (a router on the way). No raw-socket privilege is needed.
func probeTTL(ctx context.Context, dst netip.Addr, ttl, seq int) (netip.Addr, time.Duration, bool, bool) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return netip.Addr{}, 0, false, false
	}
	defer unix.Close(fd)
	if unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl) != nil || unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1) != nil {
		return netip.Addr{}, 0, false, false
	}
	if err := unix.Connect(fd, &unix.SockaddrInet4{Addr: dst.As4()}); err != nil {
		return netip.Addr{}, 0, false, false
	}
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq & 0xffff, Data: []byte("remnascope")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return netip.Addr{}, 0, false, false
	}
	start := time.Now()
	if _, err := unix.Write(fd, b); err != nil {
		return netip.Addr{}, 0, false, false
	}
	deadline := start.Add(traceProbeWait)
	for ctx.Err() == nil {
		left := time.Until(deadline)
		if left <= 0 {
			return netip.Addr{}, 0, false, false
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}
		n, err := unix.Poll(fds, int(left.Milliseconds())+1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return netip.Addr{}, 0, false, false
		}
		if n == 0 {
			continue
		}
		// An error from a router arrives on the error queue, an echo reply as ordinary data.
		if fds[0].Revents&unix.POLLERR != 0 {
			if from, ok := readQueuedError(fd); ok {
				return from, time.Since(start), false, true
			}
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			buf := make([]byte, 1500)
			rn, err := unix.Read(fd, buf)
			if err != nil {
				continue
			}
			if m, err := icmp.ParseMessage(1, buf[:rn]); err == nil && m.Type == ipv4.ICMPTypeEchoReply {
				return dst, time.Since(start), true, true
			}
		}
	}
	return netip.Addr{}, 0, false, false
}

// readQueuedError takes one message off the socket's error queue and returns the address of the
// router that sent the ICMP error, if it was one.
func readQueuedError(fd int) (netip.Addr, bool) {
	p := make([]byte, 1500)
	oob := make([]byte, 512)
	_, oobn, _, _, err := unix.Recvmsg(fd, p, oob, unix.MSG_ERRQUEUE)
	if err != nil {
		return netip.Addr{}, false
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return netip.Addr{}, false
	}
	for _, c := range cmsgs {
		// struct sock_extended_err (16 bytes) is followed by the sockaddr_in of the offender.
		if c.Header.Level == unix.IPPROTO_IP && c.Header.Type == unix.IP_RECVERR && len(c.Data) >= 16+8 {
			if c.Data[4] != 2 { // SO_EE_ORIGIN_ICMP
				continue
			}
			var a [4]byte
			copy(a[:], c.Data[16+4:16+8])
			return netip.AddrFrom4(a), true
		}
	}
	return netip.Addr{}, false
}
