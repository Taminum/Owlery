//go:build windows

package remotehelper

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procOpenInputDesktop         = user32.NewProc("OpenInputDesktop")
	procSetThreadDesktop         = user32.NewProc("SetThreadDesktop")
	procCloseDesktop             = user32.NewProc("CloseDesktop")
	procGetUserObjectInformation = user32.NewProc("GetUserObjectInformationW")
)

const (
	maximumAllowed = 0x02000000 // MAXIMUM_ALLOWED: open the desktop with everything the token is granted
	uoiName        = 2          // UOI_NAME for GetUserObjectInformation
)

// desktopGen rises whenever the capture loop notices the input desktop changed — a switch to or from the "secure
// desktop" (named "Winlogon") where UAC prompts and the lock screen live. The input loop watches it so it moves its
// own thread to the same desktop; otherwise SendInput would go to the old one and clicks on a UAC prompt would miss.
//
// Following the input desktop is the whole reason the helper runs as SYSTEM: only SYSTEM may open the secure desktop,
// and GDI capture and SendInput act on the desktop the calling thread is attached to. ffmpeg's own gdigrab cannot
// follow there, which is why the picture is captured in this process and ffmpeg is only the encoder.
var desktopGen atomic.Uint64

// follower keeps one thread attached to the input desktop. Each goroutine that captures or injects has its own, and
// must run on a thread locked with runtime.LockOSThread, because SetThreadDesktop acts on the calling thread.
type follower struct {
	hDesk uintptr
	name  string
	gen   uint64
	bound bool
}

// bindCapture moves the calling thread onto whatever desktop is receiving input right now. Called every frame by the
// capture loop; the cost of reopening is paid only when the desktop actually changed.
func (f *follower) bindCapture() {
	h, _, _ := procOpenInputDesktop.Call(0, 0, maximumAllowed)
	if h == 0 {
		return
	}
	name := desktopName(h)
	if f.bound && name == f.name {
		procCloseDesktop.Call(h)
		return
	}
	procSetThreadDesktop.Call(h)
	if f.hDesk != 0 {
		procCloseDesktop.Call(f.hDesk)
	}
	f.hDesk, f.name, f.bound = h, name, true
	desktopGen.Add(1)
}

// bindInput does the same for the injection thread, but reopens only once the capture loop has signalled a change, so
// an ordinary mouse move costs a single atomic read.
func (f *follower) bindInput() {
	g := desktopGen.Load()
	if f.bound && g == f.gen {
		return
	}
	h, _, _ := procOpenInputDesktop.Call(0, 0, maximumAllowed)
	if h == 0 {
		return
	}
	procSetThreadDesktop.Call(h)
	if f.hDesk != 0 {
		procCloseDesktop.Call(f.hDesk)
	}
	f.hDesk, f.gen, f.bound = h, g, true
}

func (f *follower) close() {
	if f.hDesk != 0 {
		procCloseDesktop.Call(f.hDesk)
		f.hDesk = 0
	}
}

func desktopName(h uintptr) string {
	var buf [64]uint16
	var need uint32
	procGetUserObjectInformation.Call(h, uoiName, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&need)))
	return windows.UTF16ToString(buf[:])
}
