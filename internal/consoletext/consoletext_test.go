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

func TestRussianAnsiBytesBecomeText(t *testing.T) {
	// "Параметры разрешений" as the ANSI page writes it, and the same word the console page cannot confuse it with.
	cp1251 := string([]byte{0xCF, 0xE0, 0xF0, 0xE0, 0xEC, 0xE5, 0xF2, 0xF0, 0xFB, ' ', 0xB8, 0xE6})
	if got := ToUTF8(cp1251); got != "Параметры ёж" {
		t.Fatalf("%q", got)
	}
	// Inside XML, next to ASCII, as wevtutil prints it: "Ошибка 7031".
	xml := "<Message>" + string([]byte{0xCE, 0xF8, 0xE8, 0xE1, 0xEA, 0xE0}) + " 7031</Message>"
	if got := ToUTF8(xml); got != "<Message>Ошибка 7031</Message>" {
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
