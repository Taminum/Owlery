package guac

import (
	"strings"
	"testing"
)

func TestInstructionsRoundTripAndCountCharacters(t *testing.T) {
	in := []Instruction{New("connect", "10.0.0.7", "3389", "админ", "пароль с пробелами", ""), New("", "uuid"), New("sync", "1")}
	var b strings.Builder
	for _, i := range in {
		b.WriteString(i.String())
	}
	if !strings.Contains(b.String(), "5.админ") {
		t.Fatalf("lengths must count characters: %q", b.String())
	}
	r := NewReader(strings.NewReader(b.String()))
	for _, want := range in {
		got, err := r.Read()
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != want.String() {
			t.Fatalf("got %q, want %q", got.String(), want.String())
		}
	}
	if _, err := NewReader(strings.NewReader("3.abc:")).Read(); err == nil {
		t.Fatal("a bad separator was accepted")
	}
}
