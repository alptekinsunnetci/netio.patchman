package web

import (
	"context"
	"slices"
	"strings"

	"netio.patchman/internal/agentsign"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// keyGroupLimit bounds the hosts listed by name per group.
const keyGroupLimit = 10

// keyGroup is a set of agents in the same signing state on the agents page.
type keyGroup struct {
	// Kind: old (agent too old to trust keys), missing (no key and none on
	// the server to pin), mismatch (trusts other keys than the server's or
	// the release's: only changeable on the host), pending (pins the
	// server's keys at its next check-in).
	Kind  string
	Count int
	Hosts []store.HostKeys // the first keyGroupLimit
}

// More is the number of hosts not listed by name.
func (g keyGroup) More() int { return g.Count - len(g.Hosts) }

// signingStatus is the "Signed agent updates" notice of the agents page.
type signingStatus struct {
	Groups []keyGroup
	// Warn: some agents need action (not only pending ones).
	Warn bool
	// EnvLine is the agent.env line with the server's keys ("" without keys).
	EnvLine string
}

// signingState sorts the agents by signing state once signing is in use
// (server keys, a signed release or an agent with keys). It returns nil
// when every agent trusts a matching key, so the notice disappears.
func (s *Server) signingState(ctx context.Context, cfg settings.Values) (*signingStatus, error) {
	hosts, err := s.st.UpdateKeyStates(ctx)
	if err != nil {
		return nil, err
	}
	// The keys an agent should trust: the server's, else the release's signers.
	want := agentsign.KeyIDs(cfg.AgentUpdateKeys)
	if len(want) == 0 {
		want = s.o.Release.Signers()
	}
	inUse := len(want) > 0
	groups := map[string]*keyGroup{}
	for _, h := range hosts {
		if len(h.UpdateKeys) > 0 {
			inUse = true
		}
		kind := ""
		switch {
		case len(h.UpdateKeys) > 0:
			if len(want) > 0 && !slices.ContainsFunc(agentsign.KeyIDs(h.UpdateKeys), func(id string) bool { return slices.Contains(want, id) }) {
				kind = "mismatch"
			}
		case !h.Supports(protocol.CapSignedUpdate):
			kind = "old"
		case len(cfg.AgentUpdateKeys) > 0:
			kind = "pending"
		default:
			kind = "missing"
		}
		if kind == "" {
			continue
		}
		g := groups[kind]
		if g == nil {
			g = &keyGroup{Kind: kind}
			groups[kind] = g
		}
		g.Count++
		if len(g.Hosts) < keyGroupLimit {
			g.Hosts = append(g.Hosts, h)
		}
	}
	if !inUse || len(groups) == 0 {
		return nil, nil
	}
	st := &signingStatus{}
	for _, kind := range []string{"mismatch", "missing", "old", "pending"} {
		if g := groups[kind]; g != nil {
			st.Groups = append(st.Groups, *g)
			st.Warn = st.Warn || kind != "pending"
		}
	}
	if len(cfg.AgentUpdateKeys) > 0 {
		st.EnvLine = "PATCHMAN_UPDATE_KEYS=" + strings.Join(cfg.AgentUpdateKeys, ",")
	}
	return st, nil
}
