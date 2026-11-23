package rollout

import (
	"sort"
	"strings"

	"netio.patchman/internal/store"
)

// Host orders within a rollout.
const (
	OrderHostname  = "hostname"
	OrderScoreAsc  = "score_asc"  // riskiest (lowest score) first
	OrderScoreDesc = "score_desc" // healthiest first: a calm canary
)

// SortHosts orders hosts for a rollout. Hosts without a score go last.
func SortHosts(hosts []store.Host, order string) {
	sort.SliceStable(hosts, func(i, j int) bool {
		a, b := hosts[i], hosts[j]
		switch order {
		case OrderScoreAsc, OrderScoreDesc:
			if (a.SecurityScore < 0) != (b.SecurityScore < 0) {
				return b.SecurityScore < 0
			}
			if a.SecurityScore != b.SecurityScore {
				if order == OrderScoreAsc {
					return a.SecurityScore < b.SecurityScore
				}
				return a.SecurityScore > b.SecurityScore
			}
		}
		if la, lb := strings.ToLower(a.Hostname), strings.ToLower(b.Hostname); la != lb {
			return la < lb
		}
		return a.ID < b.ID
	})
}

// PlanBatches splits ordered hosts into stages: the first canary hosts,
// then batches of batch hosts (0: everything else in one stage).
func PlanBatches(hosts []int64, canary, batch int) [][]int64 {
	var stages [][]int64
	if canary > 0 && len(hosts) > 0 {
		n := min(canary, len(hosts))
		stages = append(stages, append([]int64(nil), hosts[:n]...))
		hosts = hosts[n:]
	}
	for len(hosts) > 0 {
		n := len(hosts)
		if batch > 0 {
			n = min(batch, len(hosts))
		}
		stages = append(stages, append([]int64(nil), hosts[:n]...))
		hosts = hosts[n:]
	}
	return stages
}

// PlanGroups makes one stage per group, in the given order; a host in
// several groups runs with the first. The canary hosts come from the first
// group with hosts and form their own stage before it.
func PlanGroups(groups [][]int64, canary int) [][]int64 {
	seen := map[int64]bool{}
	var stages [][]int64
	canaryDone := canary <= 0
	for _, g := range groups {
		var st []int64
		for _, h := range g {
			if !seen[h] {
				seen[h] = true
				st = append(st, h)
			}
		}
		if !canaryDone && len(st) > 0 {
			n := min(canary, len(st))
			stages = append(stages, st[:n:n])
			st = st[n:]
			canaryDone = true
		}
		if len(st) > 0 {
			stages = append(stages, st)
		}
	}
	return stages
}
