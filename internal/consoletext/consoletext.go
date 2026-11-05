// Package consoletext makes what a Windows console program printed fit for a parser.
package consoletext

import (
	"strings"
	"unicode/utf8"
)

// ToUTF8: into a pipe a Windows tool writes in a legacy code page, and which one depends on the machine and on how the agent was
// started: the Russian console (cp866) or the Russian ANSI page (cp1251). Neither is UTF-8, and an XML parser stops at the first
// such byte. Text that is not valid UTF-8 is read as the page it looks like (see looksCp1251); anything left over becomes "?".
// Characters XML does not allow are dropped.
func ToUTF8(s string) string {
	if utf8.ValidString(s) {
		return StripXMLControls(s)
	}
	win := looksCp1251(s)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x80:
			b.WriteByte(c)
		case win:
			b.WriteRune(cp1251Rune(c))
		default:
			b.WriteRune(cp866Rune(c))
		}
	}
	return StripXMLControls(b.String())
}

// looksCp1251 tells the two pages apart by a vote of the bytes that can only be a letter in one of them. In cp866 the capitals are
// 0x80-0x9F (cp1251 has punctuation there), and 0xB0-0xDF is drawing characters, which no log message has; in cp1251 the
// capitals sit exactly at 0xC0-0xDF, and the lowercase ones reach 0xF2-0xFF, which cp866 uses for odd symbols. A stray byte
// in a batch does not turn it; a tie, or no clear byte at all, reads as cp866, the console page.
func looksCp1251(s string) bool {
	var win, dos int
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 0x80 && c <= 0x9F:
			dos++
		case (c >= 0xB0 && c <= 0xDF && c != 0xB8) || c >= 0xF2:
			win++
		}
	}
	return win > dos
}

func cp866Rune(c byte) rune {
	switch {
	case c >= 0x80 && c <= 0xAF:
		return rune(0x410 + int(c-0x80))
	case c >= 0xE0 && c <= 0xEF:
		return rune(0x440 + int(c-0xE0))
	case c == 0xF0:
		return 'Ё'
	case c == 0xF1:
		return 'ё'
	}
	return '?'
}

func cp1251Rune(c byte) rune {
	switch {
	case c >= 0xC0:
		return rune(0x410 + int(c-0xC0))
	case c == 0xA8:
		return 'Ё'
	case c == 0xB8:
		return 'ё'
	case c == 0xB9:
		return '№'
	case c == 0xAB:
		return '«'
	case c == 0xBB:
		return '»'
	case c == 0x96:
		return '–'
	case c == 0x97:
		return '—'
	case c == 0xA0:
		return ' '
	}
	return '?'
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
