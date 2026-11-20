package timeutil

import (
	"testing"
	"time"

	"netio.patchman/internal/i18n"
)

func TestIstanbulDisplay(t *testing.T) {
	loc, err := time.LoadLocation(DefaultTimezone)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFormatter(loc, i18n.MustLoad().Localizer(i18n.DefaultLocale))
	ts := time.Date(2026, 11, 19, 11, 30, 0, 0, time.UTC) // stored in UTC

	if got, want := f.DateTime(ts), "19.11.2026 14:30"; got != want {
		t.Errorf("DateTime = %q, want %q", got, want)
	}
	if got, want := f.Long(ts), "19 Kasım 2026 14:30"; got != want {
		t.Errorf("Long = %q, want %q", got, want)
	}
	if got, want := f.LongDate(ts), "19 Kasım 2026"; got != want {
		t.Errorf("LongDate = %q, want %q", got, want)
	}
	if got, want := f.ISO(ts.In(loc)), "2026-11-19T11:30:00Z"; got != want {
		t.Errorf("ISO = %q, want %q", got, want)
	}
	if got := f.DateTime(time.Time{}); got != "—" {
		t.Errorf("zero time = %q, want em dash", got)
	}
}

func TestNowIsUTC(t *testing.T) {
	if Now().Location() != time.UTC {
		t.Fatal("Now() must return UTC")
	}
}
