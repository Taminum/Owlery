//go:build windows

package remotehelper

// vkFor maps a JS KeyboardEvent.code (the physical key, independent of layout and of what the layout types) to a
// Windows virtual-key code and whether it is one of the "extended" keys (the navigation cluster, the right-hand
// Ctrl/Alt, the Windows keys, numpad Enter and divide): Windows tells these apart from their numpad or left-hand
// look-alikes only through that flag.
//
// The punctuation keys assume a US layout, since they are named by the US key they sit on (e.g. "BracketLeft" is
// "[" on a US keyboard, something else on others); letters, digits, and the rest are unaffected. Good enough to
// type commands and paths; a fuller mapping is easy to grow later, key by key, as a real gap turns up.
func vkFor(code string) (vk uint16, extended bool, ok bool) {
	if v, ok := letterDigitVK[code]; ok {
		return v, false, true
	}
	if v, ok := extendedVK[code]; ok {
		return v, true, true
	}
	if v, ok := plainVK[code]; ok {
		return v, false, true
	}
	return 0, false, false
}

var letterDigitVK = func() map[string]uint16 {
	m := map[string]uint16{}
	for c := byte('A'); c <= 'Z'; c++ {
		m["Key"+string(c)] = uint16(c) // VK_A..VK_Z equal the ASCII letters
	}
	for d := byte('0'); d <= '9'; d++ {
		m["Digit"+string(d)] = uint16(d) // VK_0..VK_9 equal the ASCII digits
	}
	return m
}()

// extendedVK are sent with KEYEVENTF_EXTENDEDKEY.
var extendedVK = map[string]uint16{
	"ArrowLeft": 0x25, "ArrowUp": 0x26, "ArrowRight": 0x27, "ArrowDown": 0x28,
	"Home": 0x24, "End": 0x23, "PageUp": 0x21, "PageDown": 0x22, "Insert": 0x2D, "Delete": 0x2E,
	"ControlRight": 0xA3, "AltRight": 0xA5, "MetaLeft": 0x5B, "MetaRight": 0x5C,
	"NumLock": 0x90, "NumpadDivide": 0x6F, "NumpadEnter": 0x0D,
}

var plainVK = map[string]uint16{
	"Backspace": 0x08, "Tab": 0x09, "Enter": 0x0D, "Escape": 0x1B, "Space": 0x20,
	"ShiftLeft": 0xA0, "ShiftRight": 0xA1, "ControlLeft": 0xA2, "AltLeft": 0xA4,
	"CapsLock": 0x14, "ScrollLock": 0x91, "Pause": 0x13, "PrintScreen": 0x2C, "ContextMenu": 0x5D,
	"F1": 0x70, "F2": 0x71, "F3": 0x72, "F4": 0x73, "F5": 0x74, "F6": 0x75,
	"F7": 0x76, "F8": 0x77, "F9": 0x78, "F10": 0x79, "F11": 0x7A, "F12": 0x7B,
	"Numpad0": 0x60, "Numpad1": 0x61, "Numpad2": 0x62, "Numpad3": 0x63, "Numpad4": 0x64,
	"Numpad5": 0x65, "Numpad6": 0x66, "Numpad7": 0x67, "Numpad8": 0x68, "Numpad9": 0x69,
	"NumpadMultiply": 0x6A, "NumpadAdd": 0x6B, "NumpadSubtract": 0x6D, "NumpadDecimal": 0x6E,
	"Minus": 0xBD, "Equal": 0xBB, "BracketLeft": 0xDB, "BracketRight": 0xDD,
	"Semicolon": 0xBA, "Quote": 0xDE, "Backquote": 0xC0, "Backslash": 0xDC,
	"Comma": 0xBC, "Period": 0xBE, "Slash": 0xBF,
}
