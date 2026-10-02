package i18n

import "testing"

func TestNegotiate(t *testing.T) {
	for header, want := range map[string]string{
		"":                             "en",
		"fr-FR,fr;q=0.9,en;q=0.8":      "fr",
		"en-US,en;q=0.9,fr;q=0.8":      "en",
		"de-DE,de;q=0.9,fr;q=0.5":      "fr",
		"de":                           "en",
		"fr;q=0, en":                   "en",
		"es, fr-CA;q=0.7, en-GB;q=0.6": "fr",
	} {
		if got := Negotiate(header); got != want {
			t.Errorf("Negotiate(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestT(t *testing.T) {
	Register("xx", map[string]string{"Hello, %s": "Salut, %s"})
	if got := T("xx", "Hello, %s", "Ana"); got != "Salut, Ana" {
		t.Errorf("T xx = %q", got)
	}
	if got := T("de", "Hello, %s", "Ana"); got != "Hello, Ana" {
		t.Errorf("unknown language should fall back to English, got %q", got)
	}
}

func TestSingular(t *testing.T) {
	for _, c := range []struct {
		lang string
		n    int64
		want bool
	}{{"fr", 0, true}, {"fr", 1, true}, {"fr", 2, false}, {"en", 0, false}, {"en", 1, true}, {"en", 2, false}} {
		if got := singular(c.lang, c.n); got != c.want {
			t.Errorf("singular(%s, %d) = %v", c.lang, c.n, got)
		}
	}
}
