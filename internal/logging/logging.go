// Package logging builds the structured logger. Every record carries
// app=netio.patchman so log aggregation can identify the product.
// Log messages come from the i18n catalog ("log.*" keys); attribute keys
// stay in English because they are machine-read fields.
package logging

import (
	"io"
	"log/slog"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/version"
)

// New returns a logger for component ("server", "agent", ...). Timestamps are
// written in UTC.
func New(w io.Writer, component string, level slog.Leveler, format string) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Value = slog.TimeValue(a.Value.Time().UTC())
			}
			return a
		},
	}
	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h).With(
		slog.String("app", brand.Name),
		slog.String("component", component),
		slog.String("version", version.Version),
		slog.String("codename", version.CurrentCodename()),
	)
}
