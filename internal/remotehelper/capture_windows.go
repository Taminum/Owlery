//go:build windows

package remotehelper

import (
	"fmt"
	"image"
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

// captureScreen takes one screenshot of the whole virtual screen (every monitor, as one image) through plain GDI.
// This is the simple, broadly-compatible way to read the screen; it costs a full-frame copy on every call, which is
// fine at the handful of frames per second this sends over the network, but is not the fastest Windows offers (that
// would be DXGI Desktop Duplication, a sizeable addition of its own — worth it later if GDI proves too slow).
func captureScreen() (img *image.NRGBA, err error) {
	x, y, w, h := screenBounds()
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("remotehelper: no screen (metrics %dx%d)", w, h)
	}
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil, fmt.Errorf("remotehelper: GetDC failed")
	}
	defer procReleaseDC.Call(0, screenDC)

	memDC, _, _ := procCreateCompatibleDC.Call(screenDC)
	if memDC == 0 {
		return nil, fmt.Errorf("remotehelper: CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(memDC)

	bmp, _, _ := procCreateCompatibleBitmap.Call(screenDC, uintptr(w), uintptr(h))
	if bmp == 0 {
		return nil, fmt.Errorf("remotehelper: CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(bmp)

	old, _, _ := procSelectObject.Call(memDC, bmp)
	defer procSelectObject.Call(memDC, old)

	ok, _, _ := procBitBlt.Call(memDC, 0, 0, uintptr(w), uintptr(h), screenDC, uintptr(x), uintptr(y), uintptr(srcCopy|captureBlt))
	if ok == 0 {
		return nil, fmt.Errorf("remotehelper: BitBlt failed")
	}

	var bi bitmapInfoHeader
	bi.Size = uint32(unsafe.Sizeof(bi))
	bi.Width = int32(w)
	bi.Height = -int32(h) // negative: rows come back top-down, the order image.NRGBA already expects
	bi.Planes = 1
	bi.BitCount = 32
	bi.Compression = biRGB

	raw := make([]byte, w*h*4)
	r, _, _ := procGetDIBits.Call(memDC, bmp, 0, uintptr(h), uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&bi)), dibRGBColors)
	if r == 0 {
		return nil, fmt.Errorf("remotehelper: GetDIBits failed")
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
