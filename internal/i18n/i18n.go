// Package i18n provides message catalogs for all user-facing text.
//
// Catalogs are flat JSON files in locales/<locale>.json, embedded into the
// binary. tr-TR is the default and, for now, the only shipped locale. Adding
// a language means adding a new JSON file with the same keys; no code change
// is required.
//
// Placeholders use named braces: "{count} sunucuda ..." and are filled with
// key/value pairs: l.T("email.vuln.intro", "count", 12, "cve", id).
//
// Vulnerability data (CVE identifiers, titles, descriptions, CVSS metrics,
// advisory titles, package names) is NEVER passed through this package. It is
// displayed exactly as received from its source.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"unicode"
)

// DefaultLocale is the product's primary locale.
const DefaultLocale = "tr-TR"

//go:embed locales/*.json
var localeFS embed.FS

// Bundle holds all loaded catalogs.
type Bundle struct {
	defaultLocale string
	catalogs      map[string]map[string]string
}

// Load reads every embedded catalog. It fails if the default locale is missing.
func Load() (*Bundle, error) {
	return load(localeFS, "locales")
}

// MustLoad is Load that panics on error. Catalogs are embedded at build time,
// so a failure here is a build defect, not a runtime condition.
func MustLoad() *Bundle {
	b, err := Load()
	if err != nil {
		panic(err)
	}
	return b
}

func load(fsys fs.FS, dir string) (*Bundle, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("i18n: read catalog dir: %w", err)
	}
	b := &Bundle{defaultLocale: DefaultLocale, catalogs: map[string]map[string]string{}}
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("i18n: read %s: %w", e.Name(), err)
		}
		var cat map[string]string
		if err := json.Unmarshal(raw, &cat); err != nil {
			return nil, fmt.Errorf("i18n: parse %s: %w", e.Name(), err)
		}
		b.catalogs[strings.TrimSuffix(e.Name(), ".json")] = cat
	}
	if _, ok := b.catalogs[b.defaultLocale]; !ok {
		return nil, fmt.Errorf("i18n: default locale %s not found", b.defaultLocale)
	}
	return b, nil
}

// Locales returns the available locales, sorted.
func (b *Bundle) Locales() []string {
	out := make([]string, 0, len(b.catalogs))
	for k := range b.catalogs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Supports reports whether a catalog exists for locale.
func (b *Bundle) Supports(locale string) bool {
	_, ok := b.catalogs[locale]
	return ok
}

// Keys returns every key of a locale's catalog, sorted.
func (b *Bundle) Keys(locale string) []string {
	cat := b.catalogs[locale]
	out := make([]string, 0, len(cat))
	for k := range cat {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Localizer returns a translator for locale. Unknown locales fall back to the
// default locale.
func (b *Bundle) Localizer(locale string) Localizer {
	if !b.Supports(locale) {
		locale = b.defaultLocale
	}
	return Localizer{bundle: b, locale: locale}
}

// Localizer translates keys for a single locale.
type Localizer struct {
	bundle *Bundle
	locale string
}

// Locale returns the BCP 47 locale tag, e.g. "tr-TR".
func (l Localizer) Locale() string { return l.locale }

// Lang returns the language subtag, e.g. "tr", for the HTML lang attribute.
func (l Localizer) Lang() string {
	lang, _, _ := strings.Cut(l.locale, "-")
	return lang
}

// T returns the message for key, filling {name} placeholders from args given
// as alternating name/value pairs. A missing key falls back to the default
// locale, then to the key itself so that gaps are visible rather than silent.
func (l Localizer) T(key string, args ...any) string {
	msg, ok := l.bundle.catalogs[l.locale][key]
	if !ok {
		msg, ok = l.bundle.catalogs[l.bundle.defaultLocale][key]
	}
	if !ok {
		return key
	}
	if len(args) < 2 {
		return msg
	}
	pairs := make([]string, 0, len(args))
	for i := 0; i+1 < len(args); i += 2 {
		pairs = append(pairs, "{"+fmt.Sprint(args[i])+"}", fmt.Sprint(args[i+1]))
	}
	return strings.NewReplacer(pairs...).Replace(msg)
}

// Upper converts s to upper case using the locale's casing rules. Turkish
// requires special casing: "kritik" must become "KRİTİK", not "KRITIK".
func (l Localizer) Upper(s string) string {
	if l.Lang() == "tr" || l.Lang() == "az" {
		return strings.ToUpperSpecial(unicode.TurkishCase, s)
	}
	return strings.ToUpper(s)
}

// Lower converts s to lower case using the locale's casing rules.
func (l Localizer) Lower(s string) string {
	if l.Lang() == "tr" || l.Lang() == "az" {
		return strings.ToLowerSpecial(unicode.TurkishCase, s)
	}
	return strings.ToLower(s)
}
