// Package consoletext makes what a Windows console program printed fit for a parser.
package consoletext

import (
	"strings"
	"unicode/utf8"
)

// ToUTF8: into a pipe a Windows tool writes in the console's code page, so on a Russian machine its text arrives as cp866
// bytes, which are not UTF-8, and an XML parser stops at the first of them. Text that is not valid UTF-8 is read as cp866
// (the Russian console); anything left over becomes "?". Characters XML does not allow are dropped.
func ToUTF8(s string) string {
	if utf8.ValidString(s) {
		return StripXMLControls(s)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x80:
			b.WriteByte(c)
		case c >= 0x80 && c <= 0xAF:
			b.WriteRune(rune(0x410 + int(c-0x80)))
		case c >= 0xE0 && c <= 0xEF:
			b.WriteRune(rune(0x440 + int(c-0xE0)))
		case c == 0xF0:
			b.WriteRune('Ё')
		case c == 0xF1:
			b.WriteRune('ё')
		default:
			b.WriteByte('?')
		}
	}
	return StripXMLControls(b.String())
}

// StripXMLControls drops the control characters XML does not allow; a log entry may carry any text.
func StripXMLControls(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
}

// Cut keeps at most n bytes of s without splitting a character.
func Cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
