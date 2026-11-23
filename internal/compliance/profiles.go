// Package compliance builds compliance & audit reports: one engine, one
// evidence repository (store/evidence.go), framework profiles with their own
// control lists and a separate assessment per control.
//
// A profile is a versioned list of controls (profiles/*.json). Control ids
// and titles are netio.patchman's own wording; no standard's text is copied.
// A control names the shared checks (checks.go) it relies on and how
// strongly (primary decides the automated outcome, supporting only adds
// evidence); a control without checks needs manual evidence. The same
// evidence can support controls of several profiles; that never means a
// profile's requirements are met.
package compliance

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"netio.patchman/internal/store"
)

//go:embed profiles/*.json
var profileFS embed.FS

// Relevance of a check or manual evidence for a control.
const (
	RelevancePrimary    = "primary"
	RelevanceSupporting = "supporting"
	RelevanceManual     = "manual"
)

// Manual evidence types a control can require.
const (
	ManualPolicy  = "policy"  // a documented policy
	ManualProcess = "process" // a documented process or procedure
)

// CheckRef is a check a control relies on, optionally limited to platforms.
type CheckRef struct {
	Check     string   `json:"check"`
	Relevance string   `json:"relevance"`
	Platforms []string `json:"platforms,omitempty"`
}

// Key identifies the check and platform combination.
func (c CheckRef) Key() string {
	if len(c.Platforms) == 0 {
		return c.Check
	}
	return c.Check + "[" + strings.Join(c.Platforms, ",") + "]"
}

// Control is one requirement of a profile.
type Control struct {
	ID     string     `json:"id"`
	Checks []CheckRef `json:"checks,omitempty"`
	// Manual is the documentation the control needs besides (or instead
	// of) the checks: ManualPolicy or ManualProcess.
	Manual string `json:"manual,omitempty"`
}

// TitleKey is the catalog key of the control's title; DescKey its description.
func (c Control) TitleKey(profile string) string {
	return "compliance.control." + profile + "." + keyPart(c.ID)
}

// DescKey is the catalog key of the control's description.
func (c Control) DescKey(profile string) string { return c.TitleKey(profile) + ".desc" }

func keyPart(id string) string { return strings.ToLower(strings.ReplaceAll(id, "-", "_")) }

// Profile is a versioned framework profile.
type Profile struct {
	ID       string    `json:"id"`
	Version  string    `json:"version"`
	Controls []Control `json:"controls"`
}

// Key is "id@version", the form reports store.
func (p Profile) Key() string { return p.ID + "@" + p.Version }

// NameKey is the catalog key of the profile name.
func (p Profile) NameKey() string { return "compliance.profile." + p.ID }

// Control returns a control by id.
func (p Profile) Control(id string) (Control, bool) {
	for _, c := range p.Controls {
		if c.ID == id {
			return c, true
		}
	}
	return Control{}, false
}

// ProfileOrder is the display order of the built-in profiles.
var ProfileOrder = []string{"isms", "baseline", "itsm", "general"}

var profiles = mustLoadProfiles()

func mustLoadProfiles() map[string]Profile {
	out := map[string]Profile{}
	entries, err := profileFS.ReadDir("profiles")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		data, err := profileFS.ReadFile("profiles/" + e.Name())
		if err != nil {
			panic(err)
		}
		var p Profile
		if err := json.Unmarshal(data, &p); err != nil {
			panic(fmt.Sprintf("compliance profile %s: %v", e.Name(), err))
		}
		out[p.Key()] = p
	}
	return out
}

// Profiles returns the latest version of every built-in profile in display order.
func Profiles() []Profile {
	var out []Profile
	for _, id := range ProfileOrder {
		if p, ok := Latest(id); ok {
			out = append(out, p)
		}
	}
	return out
}

// Latest returns the newest version of a profile.
func Latest(id string) (Profile, bool) {
	var best Profile
	found := false
	for _, p := range profiles {
		if p.ID == id && (!found || p.Version > best.Version) {
			best, found = p, true
		}
	}
	return best, found
}

// ProfileByKey returns a profile version ("isms@1").
func ProfileByKey(key string) (Profile, bool) {
	p, ok := profiles[key]
	return p, ok
}

// AllProfileVersions lists every stored profile version, sorted by key.
func AllProfileVersions() []Profile {
	out := make([]Profile, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// platformsValid reports whether every platform name is known.
func platformsValid(ps []string) bool {
	for _, p := range ps {
		if !store.ValidPlatform(p) {
			return false
		}
	}
	return true
}
