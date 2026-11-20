// Package timeutil enforces the time policy:
//
//   - timestamps are created and stored in UTC (use Now, never time.Now)
//   - timestamps are displayed in the configured zone, Europe/Istanbul by default
//
// The IANA time zone database is embedded, so minimal container images without
// /usr/share/zoneinfo still resolve Europe/Istanbul correctly.
package timeutil

import (
	"fmt"
	"strconv"
	"sync/atomic"
	"time"
	_ "time/tzdata" // embed tz database

	"netio.patchman/internal/i18n"
)

// DefaultTimezone is the default display time zone.
const DefaultTimezone = "Europe/Istanbul"

// Turkish numeric date layouts.
const (
	DateLayout     = "02.01.2006"
	DateTimeLayout = "02.01.2006 15:04"
	TimeLayout     = "15:04"
)

// Now returns the current time in UTC. Use it for every timestamp that is
// persisted or compared.
func Now() time.Time { return time.Now().UTC() }

// Zone is a display time zone that can be changed at runtime (it is edited
// on the server configuration page). It is safe for concurrent use.
type Zone struct{ p atomic.Pointer[time.Location] }

// NewZone returns a Zone set to loc (UTC when nil).
func NewZone(loc *time.Location) *Zone {
	z := &Zone{}
	z.Set(loc)
	return z
}

// Set changes the zone; nil means UTC.
func (z *Zone) Set(loc *time.Location) {
	if loc == nil {
		loc = time.UTC
	}
	z.p.Store(loc)
}

// Location returns the current zone.
func (z *Zone) Location() *time.Location { return z.p.Load() }

// Formatter renders UTC timestamps in a display time zone and locale.
type Formatter struct {
	zone *Zone
	l    i18n.Localizer
}

// NewFormatter returns a Formatter for the given zone and localizer.
func NewFormatter(loc *time.Location, l i18n.Localizer) Formatter {
	return NewZoneFormatter(NewZone(loc), l)
}

// NewZoneFormatter returns a Formatter that follows z.
func NewZoneFormatter(z *Zone, l i18n.Localizer) Formatter {
	return Formatter{zone: z, l: l}
}

// Location returns the display time zone.
func (f Formatter) Location() *time.Location { return f.zone.Location() }

// Zone returns the formatter's zone so it can be changed at runtime.
func (f Formatter) Zone() *Zone { return f.zone }

// Date renders "19.11.2026".
func (f Formatter) Date(t time.Time) string {
	if t.IsZero() {
		return f.l.T("common.empty")
	}
	return t.In(f.Location()).Format(DateLayout)
}

// DateTime renders "19.11.2026 14:30".
func (f Formatter) DateTime(t time.Time) string {
	if t.IsZero() {
		return f.l.T("common.empty")
	}
	return t.In(f.Location()).Format(DateTimeLayout)
}

// Long renders "19 Kasım 2026 14:30" using localized month names.
func (f Formatter) Long(t time.Time) string {
	if t.IsZero() {
		return f.l.T("common.empty")
	}
	lt := t.In(f.Location())
	return f.l.T("datetime.long",
		"day", strconv.Itoa(lt.Day()),
		"month", f.l.T(fmt.Sprintf("month.%d", int(lt.Month()))),
		"year", strconv.Itoa(lt.Year()),
		"time", lt.Format(TimeLayout),
	)
}

// LongDate renders "19 Kasım 2026".
func (f Formatter) LongDate(t time.Time) string {
	if t.IsZero() {
		return f.l.T("common.empty")
	}
	lt := t.In(f.Location())
	return f.l.T("datetime.long_date",
		"day", strconv.Itoa(lt.Day()),
		"month", f.l.T(fmt.Sprintf("month.%d", int(lt.Month()))),
		"year", strconv.Itoa(lt.Year()),
	)
}

// ISO renders an RFC 3339 UTC timestamp for machine-readable attributes,
// such as <time datetime="...">.
func (f Formatter) ISO(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
