//go:build windows

package remotehelper

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// tray is the only visible sign of this helper: an icon that exists exclusively while a session is connected, so
// that at any other moment there is nothing on screen to show for it. Right-click offers one thing, ending the
// session; nothing here asks the signed-in person for permission to start one, which is the owner's own choice made
// at the other end, in Owlery.
type tray struct {
	hwnd    uintptr
	visible atomic.Bool
}

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")

	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procPostMessage      = user32.NewProc("PostMessageW")
	procLoadIcon         = user32.NewProc("LoadIconW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wmDestroy   = 0x0002
	wmCommand   = 0x0111
	wmRButtonUp = 0x0205
	wmUser      = 0x0400
	trayMsg     = wmUser + 1

	menuEndSession = 1

	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04
	nimAdd     = 0x00000000
	nimModify  = 0x00000001
	nimDelete  = 0x00000002

	idiApplication = 32512 // a stock Windows icon, used until this project has its own

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	tpmNonotify    = 0x0080
)

type point struct{ X, Y int32 }

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// notifyIconData mirrors NOTIFYICONDATAW field for field, in order, so Go's own struct alignment reproduces the C
// layout exactly (uintptr fields are 8-byte aligned, the rest follow their natural size) without spelling out any
// padding by hand. cbSize tells Shell_NotifyIcon which version of the struct this is; most fields below are unused
// and left zero.
type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         guid
	hBalloonIcon     uintptr
}

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

var onEndSession func()

// newTray creates the window the tray icon is attached to and starts its message loop. The icon itself is not shown
// yet: call show/hide as sessions start and end. end is called (from the message loop's own goroutine) when the
// person at the machine picks "Прекратить показ" from the icon's menu.
func newTray(end func()) (*tray, error) {
	onEndSession = end
	t := &tray{}
	ready := make(chan error, 1)
	// A window only receives its messages on the thread that created it, so it is made and served on one locked thread.
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ready <- t.create()
		t.messageLoop()
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return t, nil
}

func (t *tray) create() error {
	className, _ := syscall.UTF16PtrFromString("OwleryRemoteTray")
	windowName, _ := syscall.UTF16PtrFromString("Owlery")
	hInstance, _, _ := procGetModuleHandle.Call(0)
	icon, _, _ := procLoadIcon.Call(0, uintptr(idiApplication))
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   syscall.NewCallback(trayWndProc),
		hInstance:     hInstance,
		hIcon:         icon,
		hIconSm:       icon,
		lpszClassName: className,
	}
	if r, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("remotehelper: RegisterClassExW: %w", err)
	}
	hwnd, _, err := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(windowName)),
		0, 0, 0, 0, 0, 0, 0, hInstance, 0)
	if hwnd == 0 {
		return fmt.Errorf("remotehelper: CreateWindowExW: %w", err)
	}
	t.hwnd = hwnd
	return nil
}

func (t *tray) messageLoop() {
	var msg [48]byte // MSG is well under 48 bytes on amd64; only GetMessage/DispatchMessage touch its contents
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg[0])))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg[0])))
	}
}

func trayWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch uint32(msg) {
	case trayMsg:
		if uint32(lparam) == wmRButtonUp {
			showMenu(hwnd)
		}
		return 0
	case wmCommand:
		if uint16(wparam) == menuEndSession && onEndSession != nil {
			go onEndSession()
		}
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wparam, lparam)
	return r
}

func showMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	label, _ := syscall.UTF16PtrFromString("Прекратить показ")
	procAppendMenu.Call(menu, 0, menuEndSession, uintptr(unsafe.Pointer(label)))
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// A popup menu only dismisses itself reliably if its owner window is foreground; without this, clicking
	// elsewhere can leave it stuck open.
	procSetForegroundWin.Call(hwnd)
	procTrackPopupMenu.Call(menu, tpmRightButton|tpmNonotify, uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
	procPostMessage.Call(hwnd, 0, 0, 0) // WM_NULL: without it the next menu dismissal can be missed on some shells
}

// show adds the icon, with the tooltip naming who is connected. Calling it while already shown updates the tip.
func (t *tray) show(tip string) {
	nid := t.data(tip)
	nid.uFlags = nifMessage | nifIcon | nifTip
	if t.visible.CompareAndSwap(false, true) {
		procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
		return
	}
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func (t *tray) hide() {
	if !t.visible.CompareAndSwap(true, false) {
		return
	}
	nid := t.data("")
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func (t *tray) data(tip string) notifyIconData {
	icon, _, _ := procLoadIcon.Call(0, uintptr(idiApplication))
	var nid notifyIconData
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = t.hwnd
	nid.uID = 1
	nid.uCallbackMessage = trayMsg
	nid.hIcon = icon
	copyUTF16(nid.szTip[:], tip)
	return nid
}

func (t *tray) close() {
	t.hide()
	procDestroyWindow.Call(t.hwnd)
}

func copyUTF16(dst []uint16, s string) {
	u, err := syscall.UTF16FromString(s)
	if err != nil {
		return
	}
	n := len(u)
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst, u[:n])
}
