package compliance

import (
	"context"
	"log/slog"
	"time"

	"netio.patchman/internal/eol"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// collectLimit is how many rows per source one collection reads.
const collectLimit = 5000

// Collector fills the evidence repository. Collect runs every minute from
// the maintenance loop (one writer, so the chain stays linear); Snapshot
// records the daily host states with the fleet snapshot.
type Collector struct {
	Store  *store.Store
	EOL    func() eol.Data
	Logger *slog.Logger
	L      i18n.Localizer
}

func slaOf(cfg settings.Values) store.SLA {
	return store.SLA{Critical: cfg.SLACriticalDays, High: cfg.SLAHighDays, Medium: cfg.SLAMediumDays, Low: cfg.SLALowDays}
}

// Collect copies new facts into the evidence repository; a backlog (the
// first run on an existing installation) is worked off in several rounds.
func (c *Collector) Collect(ctx context.Context) {
	cfg, err := settings.Load(ctx, c.Store)
	if err != nil {
		c.Logger.Warn(c.L.T("log.compliance.failed"), slog.String("error", err.Error()))
		return
	}
	backup := store.BackupState{LastAt: cfg.BackupLastAt, LastErrorAt: cfg.BackupLastErrorAt, LastError: cfg.BackupLastError}
	for round := 0; round < 20; round++ {
		n, err := c.Store.CollectEvidence(ctx, slaOf(cfg), backup, collectLimit)
		if err != nil {
			c.Logger.Warn(c.L.T("log.compliance.failed"), slog.String("error", err.Error()))
			return
		}
		if n > 0 {
			c.Logger.Debug(c.L.T("log.compliance.collected"), slog.Int("items", n))
		}
		if n < collectLimit {
			return
		}
	}
}

// Snapshot writes the state of every host for at's UTC day.
func (c *Collector) Snapshot(ctx context.Context, at time.Time) error {
	cfg, err := settings.Load(ctx, c.Store)
	if err != nil {
		return err
	}
	osEOL := map[int64]string{}
	if c.EOL != nil {
		hosts, err := c.Store.EOLHosts(ctx, 0)
		if err != nil {
			return err
		}
		inputs := eol.Inputs(hosts)
		for i := range inputs {
			inputs[i].Software = nil
		}
		for _, it := range eol.Assess(c.EOL(), at, cfg.EOLWarn(), inputs) {
			if it.Kind == eol.KindOS {
				osEOL[it.HostID] = it.Status
			}
		}
	}
	return c.Store.TakeHostStates(ctx, at, slaOf(cfg), osEOL)
}

// Prune removes evidence older than the retention setting.
func (c *Collector) Prune(ctx context.Context) error {
	cfg, err := settings.Load(ctx, c.Store)
	if err != nil {
		return err
	}
	return c.Store.PruneEvidence(ctx, cfg.EvidenceRetention())
}
