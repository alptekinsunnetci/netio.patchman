package drift

import (
	"context"

	"netio.patchman/internal/store"
)

// HostDrift is a host with new deviations and the standards they belong to.
type HostDrift struct {
	HostID    int64
	Hostname  string
	Count     int
	Standards []string
}

// Check evaluates every host against the standards that apply to it
// (all-hosts standards and those of its groups), stores the current
// deviations and returns the hosts with deviations not seen before.
func Check(ctx context.Context, st *store.Store) ([]HostDrift, error) {
	stds, hosts, err := st.DriftInputs(ctx)
	if err != nil {
		return nil, err
	}
	found := map[store.DriftKey]string{}
	ruleStd := map[int64]string{}
	for _, h := range hosts {
		member := map[int64]bool{}
		for _, g := range h.Groups {
			member[g] = true
		}
		var rules []Rule
		for _, s := range stds {
			if s.GroupID != 0 && !member[s.GroupID] {
				continue
			}
			for _, r := range s.Rules {
				ruleStd[r.ID] = s.Name
				rules = append(rules, Rule{ID: r.ID, StandardID: s.ID, Kind: r.Kind, SubjectType: r.SubjectType, Subject: r.Subject, Value: r.Value})
			}
		}
		if len(rules) == 0 {
			continue
		}
		facts := HostFacts{HostID: h.ID, PM: h.PackageManager, Packages: h.Packages}
		for _, s := range h.Software {
			facts.Software = append(facts.Software, Installed{Software: s.Software, Cycle: s.Cycle, PackageVersion: s.PackageVersion, Running: s.Running})
		}
		for _, v := range Evaluate(facts, rules) {
			found[store.DriftKey{HostID: h.ID, RuleID: v.RuleID}] = v.Found
		}
	}
	fresh, err := st.SyncDrift(ctx, found)
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	for _, h := range hosts {
		names[h.ID] = h.Hostname
	}
	byHost := map[int64]*HostDrift{}
	var out []HostDrift
	order := []int64{}
	for _, k := range fresh {
		hd := byHost[k.HostID]
		if hd == nil {
			hd = &HostDrift{HostID: k.HostID, Hostname: names[k.HostID]}
			byHost[k.HostID] = hd
			order = append(order, k.HostID)
		}
		hd.Count++
		if s := ruleStd[k.RuleID]; s != "" && !contains(hd.Standards, s) {
			hd.Standards = append(hd.Standards, s)
		}
	}
	for _, id := range order {
		out = append(out, *byHost[id])
	}
	return out, nil
}
