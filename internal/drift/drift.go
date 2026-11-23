// Package drift compares servers with the software standards defined for
// their groups and reports deviations (configuration drift).
//
// Versions are compared the way the host's package manager does, with the
// full distribution version ("1:2.4.57-5+deb12u2"): a distribution that
// backported a security fix raises the package revision, so a minimum
// version written as a distribution version sees the fix. A deviation is a
// policy finding, never a security finding: a different upstream number
// alone does not mean a vulnerability.
package drift

import (
	"strings"

	"netio.patchman/internal/pkgver"
	"netio.patchman/internal/software"
)

// Rule kinds.
const (
	KindRequired      = "required"       // must be installed
	KindForbidden     = "forbidden"      // must not be installed
	KindAllowedCycles = "allowed_cycles" // release cycle must be one of Value (comma separated)
	KindMinVersion    = "min_version"    // package version must be at least Value
	KindRunning       = "running"        // the software's service must be running
)

// Subject types.
const (
	SubjectSoftware = "software" // a catalog product ("nginx")
	SubjectPackage  = "package"  // an exact package name
)

// Kinds lists the rule kinds in form order.
var Kinds = []string{KindRequired, KindForbidden, KindAllowedCycles, KindMinVersion, KindRunning}

// Rule is one rule of a standard.
type Rule struct {
	ID          int64
	StandardID  int64
	Kind        string
	SubjectType string
	Subject     string
	Value       string
}

// Installed is a product release on a host (see package software).
type Installed struct {
	Software       string
	Cycle          string
	PackageVersion string
	Running        int // 1 yes, 0 no, -1 unknown
}

// HostFacts is what the rules are checked against.
type HostFacts struct {
	HostID   int64
	PM       string
	Packages map[string][]string // package name -> installed versions (one per architecture)
	Software []Installed
}

// Violation is a rule a host does not meet. Found holds the observed
// versions, cycles or state, verbatim.
type Violation struct {
	RuleID int64
	Found  string
}

func splitList(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		out = append(out, strings.TrimSpace(f))
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Valid reports whether a rule is well formed.
func Valid(r Rule) bool {
	if r.SubjectType == SubjectSoftware {
		if _, ok := software.ByID(r.Subject); !ok {
			return false
		}
	} else if r.SubjectType != SubjectPackage || r.Subject == "" {
		return false
	}
	switch r.Kind {
	case KindRequired, KindForbidden:
		return true
	case KindAllowedCycles:
		return len(splitList(r.Value)) > 0
	case KindMinVersion:
		return strings.TrimSpace(r.Value) != ""
	case KindRunning:
		return r.SubjectType == SubjectSoftware
	}
	return false
}

// observed is one installation of the rule's subject.
type observed struct {
	cycle, version string
	running        int
}

func (h HostFacts) observe(r Rule) []observed {
	var out []observed
	if r.SubjectType == SubjectSoftware {
		for _, s := range h.Software {
			if s.Software == r.Subject {
				out = append(out, observed{cycle: s.Cycle, version: s.PackageVersion, running: s.Running})
			}
		}
		return out
	}
	for _, v := range h.Packages[r.Subject] {
		out = append(out, observed{cycle: pkgver.MajorMinor(pkgver.Upstream(h.PM, v)), version: v, running: -1})
	}
	return out
}

// Evaluate checks a host against rules.
func Evaluate(h HostFacts, rules []Rule) []Violation {
	var out []Violation
	for _, r := range rules {
		obs := h.observe(r)
		var found []string
		add := func(s string) {
			if s != "" && !contains(found, s) {
				found = append(found, s)
			}
		}
		violated := false
		switch r.Kind {
		case KindRequired:
			violated = len(obs) == 0
		case KindForbidden:
			for _, o := range obs {
				add(o.version)
			}
			violated = len(obs) > 0
		case KindAllowedCycles:
			allowed := splitList(r.Value)
			for _, o := range obs {
				if !contains(allowed, o.cycle) {
					add(o.cycle)
					violated = true
				}
			}
		case KindMinVersion:
			min := strings.TrimSpace(r.Value)
			for _, o := range obs {
				if pkgver.Compare(h.PM, o.version, min) < 0 {
					add(o.version)
					violated = true
				}
			}
		case KindRunning:
			// Unknown state (old agents) is not reported as a deviation.
			for _, o := range obs {
				if o.running == 0 {
					violated = true
				}
			}
		}
		if violated {
			out = append(out, Violation{RuleID: r.ID, Found: strings.Join(found, ", ")})
		}
	}
	return out
}
