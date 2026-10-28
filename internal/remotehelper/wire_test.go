//go:build windows

package remotehelper

import (
	"bytes"
	"testing"
)

func TestMessagesRoundTripAndAreBounded(t *testing.T) {
	var b bytes.Buffer
	if err := writeFrame(&b, 1920, 1080, []byte("jpeg")); err != nil {
		t.Fatal(err)
	}
	typ, p, err := readMsg(&b)
	if err != nil || typ != msgFrame || len(p) != 8 || p[0] != 0x07 || p[1] != 0x80 {
		t.Fatalf("%v %v %v", typ, p, err)
	}
	// A header that promises more than the cap is refused before anything is allocated.
	if _, _, err := readMsg(bytes.NewReader([]byte{msgFrame, 0xff, 0xff, 0xff, 0xff})); err == nil {
		t.Fatal("an oversized message was accepted")
	}
}

func TestInputParsing(t *testing.T) {
	if _, ok := parseMouse([]byte{1, 2, 3}); ok {
		t.Fatal("a short mouse event was accepted")
	}
	m, ok := parseMouse([]byte{0xff, 0xff, 0, 0, 5, 0xff, 0xff})
	if !ok || m.X != 65535 || m.Y != 0 || m.Buttons != 5 || m.Wheel != -1 {
		t.Fatalf("%+v", m)
	}
	if _, ok := parseKey([]byte{1, 5, 'K', 'e'}); ok {
		t.Fatal("a key event with a wrong length was accepted")
	}
	k, ok := parseKey(append([]byte{1, 4}, "KeyA"...))
	if !ok || !k.Down || k.Code != "KeyA" {
		t.Fatalf("%+v", k)
	}
	if _, _, ok := vkFor("KeyA"); !ok {
		t.Fatal("KeyA has no mapping")
	}
	if _, _, ok := vkFor("Nonsense"); ok {
		t.Fatal("an unknown code was mapped")
	}
}
