package site

import "testing"

func TestOf(t *testing.T) {
	for in, want := range map[string]string{
		"www.pixiv.net":        "pixiv.net",
		"i.ytimg.com":          "ytimg.com",
		"A.B.Example.CO.UK.":   "example.co.uk",
		"example.com":          "example.com",
		"foo.github.io":        "foo.github.io", // github.io is a public suffix: each user is a site
		"v.sankakucomplex.com": "sankakucomplex.com",
		"localhost":            "localhost",
		"com":                  "com",
		"198.18.0.5":           "",
		"2001:db8::1":          "",
		"":                     "",
		"  api.telegram.org  ": "telegram.org",
		"xn--80ak6aa92e.com":   "xn--80ak6aa92e.com",
	} {
		if got := Of(in); got != want {
			t.Errorf("Of(%q) = %q, want %q", in, got, want)
		}
	}
}
