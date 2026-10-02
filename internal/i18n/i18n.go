// Package i18n translates the user interface. Messages are keyed by their
// English text (gettext-style): English needs no catalog, and an untranslated
// message falls back to English instead of showing a key. Catalogs register
// themselves from init functions, one file per area of the UI.
package i18n

import (
	"fmt"
	"strconv"
	"strings"
)

// Default is the source language of every message.
const Default = "en"

// Language is a supported UI language.
type Language struct {
	Code string // BCP 47 base tag, e.g. "fr"
	Name string // native name, for the language picker
}

// Languages lists the supported languages, in picker order.
var Languages = []Language{{"en", "English"}, {"fr", "Français"}}

var catalogs = map[string]map[string]string{}

// Register adds translations for lang. A message registered twice must carry
// the same translation, so split catalogs cannot silently disagree.
func Register(lang string, messages map[string]string) {
	c := catalogs[lang]
	if c == nil {
		c = map[string]string{}
		catalogs[lang] = c
	}
	for msg, tr := range messages {
		if prev, ok := c[msg]; ok && prev != tr {
			panic(fmt.Sprintf("i18n: conflicting %s translations for %q: %q vs %q", lang, msg, prev, tr))
		}
		c[msg] = tr
	}
}

// Supported reports whether lang is a supported language code.
func Supported(lang string) bool {
	for _, l := range Languages {
		if l.Code == lang {
			return true
		}
	}
	return false
}

// Lookup returns the translation of msg in lang, and whether one exists.
func Lookup(lang, msg string) (string, bool) {
	tr, ok := catalogs[lang][msg]
	return tr, ok
}

// T translates msg into lang, then formats it with args (fmt verbs) when
// there are any. Unknown languages and missing translations use English.
func T(lang, msg string, args ...any) string {
	if tr, ok := catalogs[lang][msg]; ok {
		msg = tr
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

// N picks the singular or plural message for n and formats n into it, e.g.
// N(lang, n, "%d member", "%d members"). French uses the singular for 0
// and 1, English only for 1.
func N(lang string, n int64, one, other string) string {
	msg := other
	if singular(lang, n) {
		msg = one
	}
	return T(lang, msg, n)
}

func singular(lang string, n int64) bool {
	if lang == "fr" {
		return n == 0 || n == 1
	}
	return n == 1
}

// Negotiate picks the best supported language from an Accept-Language
// header, or Default.
func Negotiate(acceptLanguage string) string {
	best, bestQ := Default, -1.0
	for i, part := range strings.Split(acceptLanguage, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		base, _, _ := strings.Cut(strings.ToLower(tag), "-")
		// Earlier tags win ties, as browsers list them by preference.
		if q > 0 && Supported(base) && (q > bestQ || (q == bestQ && i == 0)) {
			best, bestQ = base, q
		}
	}
	return best
}
