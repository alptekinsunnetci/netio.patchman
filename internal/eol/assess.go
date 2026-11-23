package eol

import (
	"sort"
	"time"

	"netio.patchman/internal/software"
)

// Item kinds.
const (
	KindOS       = "os"
	KindSoftware = "software"
)

// HostInput is what the assessment needs to know about a host.
type HostInput struct {
	ID             int64
	Hostname       string
	OSID           string
	OSVersionID    string
	OSName         string
	Kernel         string
	PackageManager string
	Software       []SoftwareInput
}

// SoftwareInput is a product release on a host (see package software).
type SoftwareInput struct {
	Software       string
	Cycle          string
	Version        string
	PackageVersion string
}

// Item is the support status of one operating system or product release
// on one host.
type Item struct {
	HostID   int64
	Hostname string
	Kind     string // KindOS or KindSoftware
	Software string // catalog id for software items
	Target
	Version string // upstream version (software) or OS name
	Release Release
	Found   bool // a calendar entry exists
	Status  string
	// DistroSupported: the software package is a distribution build on a
	// supported operating system, so the distribution keeps patching it
	// after the upstream end of life.
	DistroSupported bool
}

// Assess evaluates the hosts at now with the warning period warn.
func Assess(d Data, now time.Time, warn time.Duration, hosts []HostInput) []Item {
	var out []Item
	for _, h := range hosts {
		osSupported := false
		if t, ok := d.ForOS(h.OSID, h.OSVersionID, h.OSName, h.Kernel); ok {
			it := Item{HostID: h.ID, Hostname: h.Hostname, Kind: KindOS, Target: t, Version: h.OSName, Status: StatusUnknown}
			if r, ok := d.Find(t.Product, t.Cycle); ok {
				it.Release, it.Found, it.Status = r, true, r.Status(now, warn)
			}
			osSupported = it.Found && it.Status != StatusEOL
			out = append(out, it)
		}
		for _, s := range h.Software {
			def, ok := software.ByID(s.Software)
			if !ok || def.EOL == "" || s.Cycle == "" {
				continue
			}
			it := Item{HostID: h.ID, Hostname: h.Hostname, Kind: KindSoftware, Software: s.Software,
				Target: Target{Product: def.EOL, Cycle: s.Cycle, Name: def.Name}, Version: s.Version, Status: StatusUnknown}
			if r, ok := d.Find(def.EOL, s.Cycle); ok {
				it.Release, it.Found, it.Status = r, true, r.Status(now, warn)
			}
			it.DistroSupported = osSupported && DistroPackage(h.PackageManager, s.PackageVersion)
			out = append(out, it)
		}
	}
	return out
}

// Group is the items of one release (product and cycle) across hosts.
type Group struct {
	Kind     string
	Software string
	Target
	Release Release
	Found   bool
	Status  string
	Hosts   []Item
	// DistroSupported counts hosts whose package the distribution maintains.
	DistroSupported int
}

// GroupItems groups items by kind, product and cycle: out of support first,
// then by end date.
func GroupItems(items []Item) []Group {
	idx := map[[4]string]int{}
	var out []Group
	for _, it := range items {
		k := [4]string{it.Kind, it.Product, it.Cycle, it.Name}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, Group{Kind: it.Kind, Software: it.Software, Target: it.Target, Release: it.Release, Found: it.Found, Status: it.Status})
		}
		out[i].Hosts = append(out[i].Hosts, it)
		if it.DistroSupported {
			out[i].DistroSupported++
		}
	}
	rank := map[string]int{StatusEOL: 0, StatusSoon: 1, StatusUnknown: 2, StatusSupported: 3}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		if !a.Release.EOL.Equal(b.Release.EOL) {
			if a.Release.EOL.IsZero() || b.Release.EOL.IsZero() {
				return b.Release.EOL.IsZero()
			}
			return a.Release.EOL.Before(b.Release.EOL)
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Cycle < b.Cycle
	})
	return out
}

// Summary counts hosts (OS) and installations (software) by status.
type Summary struct {
	OSEOL, OSSoon, SoftwareEOL, SoftwareSoon int
	// SoftwareEOLDistro: out-of-support software maintained by the distribution.
	SoftwareEOLDistro int
}

// Summarize counts the items.
func Summarize(items []Item) Summary {
	var s Summary
	for _, it := range items {
		switch {
		case it.Kind == KindOS && it.Status == StatusEOL:
			s.OSEOL++
		case it.Kind == KindOS && it.Status == StatusSoon:
			s.OSSoon++
		case it.Kind == KindSoftware && it.Status == StatusEOL && it.DistroSupported:
			s.SoftwareEOLDistro++
		case it.Kind == KindSoftware && it.Status == StatusEOL:
			s.SoftwareEOL++
		case it.Kind == KindSoftware && it.Status == StatusSoon:
			s.SoftwareSoon++
		}
	}
	return s
}
