package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/i18n"
)

var (
	// Template calls: {{t "msg" ...}}, (t "msg"), {{tn .N "one" "other"}}.
	tplT  = regexp.MustCompile(`[{(\s]t\s+("(?:[^"\\]|\\.)*")`)
	tplTN = regexp.MustCompile(`[{(\s]tn\s+[^"\s]+\s+("(?:[^"\\]|\\.)*")\s+("(?:[^"\\]|\\.)*")`)
	// Go calls: s.t(r, "msg"), i18n.T(lang, "msg"), i18n.N(lang, n, "one", "other").
	goT  = regexp.MustCompile(`\.t\(\s*r\s*,\s*("(?:[^"\\]|\\.)*")`)
	goIT = regexp.MustCompile(`i18n\.T\(\s*[\w.()]+\s*,\s*("(?:[^"\\]|\\.)*")`)
	goIN = regexp.MustCompile(`i18n\.N\(\s*[\w.()]+\s*,\s*[^,]+,\s*("(?:[^"\\]|\\.)*")\s*,\s*("(?:[^"\\]|\\.)*")`)
	// Page titles are passed in English and translated by the layout.
	goTitle = regexp.MustCompile(`Title:\s*("(?:[^"\\]|\\.)*")`)
	// errorf("msg", ...) and msgid("msg") mark messages translated later.
	goDeferred = regexp.MustCompile(`\b(?:errorf|msgid)\(\s*("(?:[^"\\]|\\.)*")`)
	verb       = regexp.MustCompile(`%[-+# 0]*\d*(?:\.\d+)?[a-zA-Z]`)
)

// translatableMessages collects every message the UI can show in a
// translatable way, keyed by message with a sample location.
func translatableMessages(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	add := func(quoted, where string) {
		msg, err := strconv.Unquote(quoted)
		if err != nil {
			t.Fatalf("%s: cannot unquote %s: %v", where, quoted, err)
		}
		if _, ok := found[msg]; !ok {
			found[msg] = where
		}
	}
	scan := func(pattern string, res ...*regexp.Regexp) {
		files, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, re := range res {
				for _, m := range re.FindAllStringSubmatch(string(b), -1) {
					for _, q := range m[1:] {
						add(q, f)
					}
				}
			}
		}
	}
	scan("templates/*.html", tplT, tplTN)
	scan("*.go", goT, goIT, goIN, goTitle, goDeferred)
	for _, msg := range jsMessages {
		add(strconv.Quote(msg), "lang.go jsMessages")
	}
	for _, p := range integrationPresets {
		add(strconv.Quote(p.Name), "integration presets")
	}
	for _, a := range audit.Actions {
		add(strconv.Quote(audit.Label(a)), "audit labels")
	}
	return found
}

// Every translatable message has a French translation using the same
// format verbs, in the same order.
func TestFrenchCatalogComplete(t *testing.T) {
	msgs := translatableMessages(t)
	if len(msgs) < 50 {
		t.Fatalf("only %d translatable messages found: the extraction patterns are probably broken", len(msgs))
	}
	missing := 0
	for msg, where := range msgs {
		tr, ok := i18n.Lookup("fr", msg)
		if !ok {
			missing++
			t.Errorf("missing French translation (%s): %q", where, msg)
			continue
		}
		if a, b := verb.FindAllString(msg, -1), verb.FindAllString(tr, -1); strings.Join(a, " ") != strings.Join(b, " ") {
			t.Errorf("format verbs differ for %q: %v vs %v in %q", msg, a, b, tr)
		}
	}
	if missing > 0 {
		t.Logf("%d of %d messages lack a French translation", missing, len(msgs))
	}
}
