//go:build windows

package remotehelper

import (
	"fmt"
	"image"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procGetDC                  = user32.NewProc("GetDC")
	procReleaseDC              = user32.NewProc("ReleaseDC")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
)

// Virtual-screen metrics (GetSystemMetrics indices): the rectangle covering every monitor, which may start at a
// negative x or y when a monitor is placed left of or above the primary one.
const (
	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79
)

const (
	srcCopy      = 0x00CC0020
	captureBlt   = 0x40000000 // includes layered/transparent windows in the capture
	biRGB        = 0
	dibRGBColors = 0
)

type bitmapInfoHeader struct {
	Size          uint32
	Width, Height int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// screenBounds is the virtual screen in desktop coordinates: x, y may be negative.
func screenBounds() (x, y, w, h int) {
	gx, _, _ := procGetSystemMetrics.Call(smXVirtualScreen)
	gy, _, _ := procGetSystemMetrics.Call(smYVirtualScreen)
	gw, _, _ := procGetSystemMetrics.Call(smCXVirtualScreen)
	gh, _, _ := procGetSystemMetrics.Call(smCYVirtualScreen)
	return int(int32(gx)), int(int32(gy)), int(int32(gw)), int(int32(gh))
}

// monRect is one monitor in virtual-desktop pixels.
type monRect struct {
	X, Y, W, H int
	Primary    bool
}

type rect32 struct{ Left, Top, Right, Bottom int32 }

var (
	procEnumDisplayMonitors = user32.NewProc("EnumDisplayMonitors")
	procGetMonitorInfo      = user32.NewProc("GetMonitorInfoW")
	enumMu                  sync.Mutex
	enumOut                 []monRect
	enumCb                  = syscall.NewCallback(enumProc)
	// curMonitor is the monitor the session shows, an index into monitors(); 0 is the primary.
	curMonitor atomic.Int32
)

func enumProc(hm, _, _, _ uintptr) uintptr {
	var mi struct {
		Size          uint32
		Monitor, Work rect32
		Flags         uint32
	}
	mi.Size = uint32(unsafe.Sizeof(mi))
	if r, _, _ := procGetMonitorInfo.Call(hm, uintptr(unsafe.Pointer(&mi))); r != 0 {
		enumOut = append(enumOut, monRect{int(mi.Monitor.Left), int(mi.Monitor.Top), int(mi.Monitor.Right - mi.Monitor.Left), int(mi.Monitor.Bottom - mi.Monitor.Top), mi.Flags&1 != 0})
	}
	return 1
}

// monitors lists the monitors, the primary first and the rest left to right: the order the browser's buttons use.
func monitors() []monRect {
	enumMu.Lock()
	defer enumMu.Unlock()
	enumOut = nil
	procEnumDisplayMonitors.Call(0, 0, enumCb, 0)
	out := append([]monRect(nil), enumOut...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		return out[i].X < out[j].X
	})
	return out
}

// selectedMonitor is the monitor being shown; with no monitor information, the whole virtual screen.
func selectedMonitor() monRect {
	ms := monitors()
	if len(ms) == 0 {
		x, y, w, h := screenBounds()
		return monRect{x, y, w, h, true}
	}
	i := int(curMonitor.Load())
	if i < 0 || i >= len(ms) {
		i = 0
	}
	return ms[i]
}

// captureRaw takes one screenshot of the selected monitor (every monitor, as one image) through plain GDI and
// returns it as top-down BGRA bytes — the order Windows gives and the order ffmpeg's "bgra" input wants, so the video
// path feeds this straight to the encoder with no conversion. The thread the caller runs on decides which desktop is
// read: bind it to the input desktop first (see follower) so the secure desktop is captured like any other.
//
// GDI is the simple, broadly-compatible way to read the screen. It is not the fastest Windows offers (that would be
// DXGI Desktop Duplication, a sizeable addition of its own), but it can follow onto the secure desktop, which Desktop
// Duplication cannot — the deciding reason to use it here.
func captureRaw() (pix []byte, w, h int, err error) {
	m := selectedMonitor()
	x, y, w, h := m.X, m.Y, m.W, m.H
	if w <= 0 || h <= 0 {
		return nil, 0, 0, fmt.Errorf("remotehelper: no screen (metrics %dx%d)", w, h)
	}
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil, 0, 0, fmt.Errorf("remotehelper: GetDC failed")
	}
	defer procReleaseDC.Call(0, screenDC)

	memDC, _, _ := procCreateCompatibleDC.Call(screenDC)
	if memDC == 0 {
		return nil, 0, 0, fmt.Errorf("remotehelper: CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(memDC)

	bmp, _, _ := procCreateCompatibleBitmap.Call(screenDC, uintptr(w), uintptr(h))
	if bmp == 0 {
		return nil, 0, 0, fmt.Errorf("remotehelper: CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(bmp)

	old, _, _ := procSelectObject.Call(memDC, bmp)
	defer procSelectObject.Call(memDC, old)

	ok, _, _ := procBitBlt.Call(memDC, 0, 0, uintptr(w), uintptr(h), screenDC, uintptr(x), uintptr(y), uintptr(srcCopy|captureBlt))
	if ok == 0 {
		return nil, 0, 0, fmt.Errorf("remotehelper: BitBlt failed")
	}

	var bi bitmapInfoHeader
	bi.Size = uint32(unsafe.Sizeof(bi))
	bi.Width = int32(w)
	bi.Height = -int32(h) // negative: rows come back top-down
	bi.Planes = 1
	bi.BitCount = 32
	bi.Compression = biRGB

	raw := make([]byte, w*h*4)
	r, _, _ := procGetDIBits.Call(memDC, bmp, 0, uintptr(h), uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&bi)), dibRGBColors)
	if r == 0 {
		return nil, 0, 0, fmt.Errorf("remotehelper: GetDIBits failed")
	}
	return raw, w, h, nil
}

// captureScreen is the JPEG fallback's view of the screen: captureRaw turned into an opaque image.
func captureScreen() (*image.NRGBA, error) {
	raw, w, h, err := captureRaw()
	if err != nil {
		return nil, err
	}
	out := image.NewNRGBA(image.Rect(0, 0, w, h))
	// GDI hands back BGRA with the alpha byte unset; the picture itself is fully opaque.
	for i := 0; i < w*h; i++ {
		b, g, r := raw[i*4], raw[i*4+1], raw[i*4+2]
		out.Pix[i*4], out.Pix[i*4+1], out.Pix[i*4+2], out.Pix[i*4+3] = r, g, b, 255
	}
	return out, nil
}

var procSetProcessDPIAware = user32.NewProc("SetProcessDPIAware")

// makeDPIAware makes the helper see real pixels instead of a scaled-down desktop, so the picture is sharp and the mouse
// lands where the administrator clicked.
func makeDPIAware() { procSetProcessDPIAware.Call() }
