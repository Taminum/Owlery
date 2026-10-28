//go:build windows

package remotehelper

import (
	"encoding/binary"
	"unsafe"
)

var (
	procSendInput     = user32.NewProc("SendInput")
	procMapVirtualKey = user32.NewProc("MapVirtualKeyW")
)

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseMoveAbs     = 0x8001 // MOVE | ABSOLUTE
	mouseVirtualDesk = 0x4000 // coordinates cover every monitor, not just the primary
	mouseLeftDown    = 0x0002
	mouseLeftUp      = 0x0004
	mouseRightDown   = 0x0008
	mouseRightUp     = 0x0010
	mouseMiddleDown  = 0x0020
	mouseMiddleUp    = 0x0040
	mouseWheel       = 0x0800

	keyExtended = 0x0001
	keyKeyUp    = 0x0002
	keyScancode = 0x0008

	mapvkVkToVsc = 0
)

// input mirrors the Win32 INPUT struct's layout on amd64: a 4-byte type, 4 bytes of padding so the union that
// follows lands on an 8-byte boundary (its largest member ends in a pointer-sized field), then 32 bytes of union,
// which is exactly big enough for MOUSEINPUT or KEYBDINPUT. The union is filled by hand below rather than modelled
// as a Go union (which does not exist), so the byte layout is spelled out field by field instead.
type input struct {
	typ  uint32
	_    uint32
	data [32]byte
}

func mouseInputRaw(dx, dy int32, mouseData uint32, flags uint32) input {
	var in input
	in.typ = inputMouse
	binary.LittleEndian.PutUint32(in.data[0:4], uint32(dx))
	binary.LittleEndian.PutUint32(in.data[4:8], uint32(dy))
	binary.LittleEndian.PutUint32(in.data[8:12], mouseData)
	binary.LittleEndian.PutUint32(in.data[12:16], flags)
	return in
}

func keybdInputRaw(scan uint16, flags uint32) input {
	var in input
	in.typ = inputKeyboard
	binary.LittleEndian.PutUint16(in.data[0:2], 0) // wVk left at 0: we send by scan code (see scanCodeFor)
	binary.LittleEndian.PutUint16(in.data[2:4], scan)
	binary.LittleEndian.PutUint32(in.data[4:8], flags)
	return in
}

func sendInput(ins ...input) {
	if len(ins) == 0 {
		return
	}
	procSendInput.Call(uintptr(len(ins)), uintptr(unsafe.Pointer(&ins[0])), unsafe.Sizeof(ins[0]))
}

func scanCodeFor(vk uint16) uint16 {
	r, _, _ := procMapVirtualKey.Call(uintptr(vk), mapvkVkToVsc)
	return uint16(r)
}

// applyMouse moves the pointer to the normalised position and applies the buttons and wheel that changed since the
// last event. The caller (server.go) tracks the previous button state and passes only the buttons now held, so a
// button already down is not pressed again.
func applyMouse(ev mouseEvent, prevButtons uint8) {
	sendInput(mouseInputRaw(int32(ev.X), int32(ev.Y), 0, mouseMoveAbs|mouseVirtualDesk))
	changed := ev.Buttons ^ prevButtons
	if changed&1 != 0 {
		flag := uint32(mouseLeftUp)
		if ev.Buttons&1 != 0 {
			flag = mouseLeftDown
		}
		sendInput(mouseInputRaw(0, 0, 0, flag))
	}
	if changed&2 != 0 {
		flag := uint32(mouseRightUp)
		if ev.Buttons&2 != 0 {
			flag = mouseRightDown
		}
		sendInput(mouseInputRaw(0, 0, 0, flag))
	}
	if changed&4 != 0 {
		flag := uint32(mouseMiddleUp)
		if ev.Buttons&4 != 0 {
			flag = mouseMiddleDown
		}
		sendInput(mouseInputRaw(0, 0, 0, flag))
	}
	if ev.Wheel != 0 {
		sendInput(mouseInputRaw(0, 0, uint32(int32(ev.Wheel)*120), mouseWheel))
	}
}

// applyKey presses or releases one key. A code this table does not know is ignored rather than guessed: a wrong key
// landing in a password field is worse than one that does nothing.
func applyKey(ev keyEvent) {
	vk, extended, ok := vkFor(ev.Code)
	if !ok {
		return
	}
	flags := uint32(keyScancode)
	if extended {
		flags |= keyExtended
	}
	if !ev.Down {
		flags |= keyKeyUp
	}
	sendInput(keybdInputRaw(scanCodeFor(vk), flags))
}
