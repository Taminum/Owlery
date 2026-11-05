package consoletext

import "testing"

func TestRussianConsoleBytesBecomeText(t *testing.T) {
	cp866 := string([]byte{0x8F, 0xE0, 0xA8, 0xA2, 0xA5, 0xE2}) // "Привет"
	if got := ToUTF8(cp866); got != "Привет" {
		t.Fatalf("%q", got)
	}
	if got := ToUTF8("уже UTF-8\x01"); got != "уже UTF-8" {
		t.Fatalf("%q", got)
	}
}

func TestCutDoesNotSplitACharacter(t *testing.T) {
	if got := Cut("ааа", 3); got != "а" {
		t.Fatalf("%q", got)
	}
	if got := Cut("abc", 10); got != "abc" {
		t.Fatalf("%q", got)
	}
}
