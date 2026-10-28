//go:build windows

// Package remotehelper is the machine's own side of remote control: it runs in the signed-in person's session (the
// agent itself is a system service and cannot see a desktop at all), captures that screen, injects mouse and
// keyboard, and shows a tray icon only while a session is live. It speaks a small protocol of its own, carried
// unchanged through the agent and Owlery to the browser: nobody in between needs to understand it, which keeps
// Owlery's own relay a plain copy of bytes, same as the terminal's.
//
// Wire format, both on the loopback connection from the agent and (unchanged) all the way to the browser:
// [1 byte type][4 bytes big-endian length][payload]. One extra rule applies only to the loopback connection: the
// very first bytes a peer sends, before any framed message, must be the shared secret from the helper's install, or
// the connection is closed at once — that is what stops any other local process from driving the screen.
package remotehelper

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	msgFrame = 0x01 // helper -> browser: one screen update
	msgMouse = 0x02 // browser -> helper: pointer position, buttons, wheel
	msgKey   = 0x03 // browser -> helper: one key press or release
	msgError = 0x04 // helper -> browser: the session could not start, with why, in Russian
	msgEnd   = 0x05 // helper -> browser: the person at the machine pressed "Прекратить"
)

// maxMsg bounds one message. A screen frame is the only message expected to be large.
const maxMsg = 16 << 20

func writeMsg(w io.Writer, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// writeFrame sends one screen update: width and height of the image that follows, then the JPEG bytes themselves.
func writeFrame(w io.Writer, width, height int, jpg []byte) error {
	payload := make([]byte, 4+len(jpg))
	binary.BigEndian.PutUint16(payload[0:2], uint16(width))
	binary.BigEndian.PutUint16(payload[2:4], uint16(height))
	copy(payload[4:], jpg)
	return writeMsg(w, msgFrame, payload)
}

func writeError(w io.Writer, message string) error {
	return writeMsg(w, msgError, []byte(message))
}

func readMsg(r io.Reader) (typ byte, payload []byte, err error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxMsg {
		return 0, nil, fmt.Errorf("remotehelper: message too long (%d bytes)", n)
	}
	payload = make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[0], payload, nil
}

// mouseEvent is one pointer update: X and Y are normalised to 0..65535 of the virtual screen (all monitors as one
// rectangle), the way Windows itself wants absolute coordinates.
type mouseEvent struct {
	X, Y    uint16
	Buttons uint8 // bit 0 left, bit 1 right, bit 2 middle
	Wheel   int16 // vertical wheel delta, signed
}

func parseMouse(p []byte) (mouseEvent, bool) {
	if len(p) != 7 {
		return mouseEvent{}, false
	}
	return mouseEvent{
		X:       binary.BigEndian.Uint16(p[0:2]),
		Y:       binary.BigEndian.Uint16(p[2:4]),
		Buttons: p[4],
		Wheel:   int16(binary.BigEndian.Uint16(p[5:7])),
	}, true
}

// keyEvent is one key press or release. Code is a JS KeyboardEvent.code ("KeyA", "ControlLeft", "Enter", ...): the
// physical key, not the character, so the mapping does not depend on the browser's own keyboard layout guess.
type keyEvent struct {
	Down bool
	Code string
}

func parseKey(p []byte) (keyEvent, bool) {
	if len(p) < 2 {
		return keyEvent{}, false
	}
	n := int(p[1])
	if len(p) != 2+n {
		return keyEvent{}, false
	}
	return keyEvent{Down: p[0] != 0, Code: string(p[2 : 2+n])}, true
}
