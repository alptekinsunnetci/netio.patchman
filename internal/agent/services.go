package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
)

// ListServices returns the host's services with their state: systemd units,
// OpenRC services or Windows services. Names are verbatim, systemd units
// without the ".service" suffix.
func ListServices(ctx context.Context) ([]protocol.Service, error) {
	return listServices(ctx)
}

// linuxServices reads systemd, or OpenRC on systems without systemd.
func linuxServices(ctx context.Context) ([]protocol.Service, error) {
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		units, _, err := run(ctx, time.Minute, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
		if err != nil {
			return nil, err
		}
		files, _, err := run(ctx, time.Minute, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
		if err != nil {
			return nil, err
		}
		return parseSystemd(units, files), nil
	}
	if _, err := exec.LookPath("rc-status"); err == nil {
		status, _, err := run(ctx, time.Minute, "rc-status", "--all", "--nocolor")
		if err != nil {
			return nil, err
		}
		return parseOpenRC(status), nil
	}
	return nil, errors.New("no service manager")
}

// parseSystemd combines "systemctl list-units --all" (loaded units and their
// state) with "systemctl list-unit-files" (all units and whether they start
// at boot). Template units ("getty@.service") are left out.
func parseSystemd(units, files []byte) []protocol.Service {
	byName := map[string]*protocol.Service{}
	var order []string
	add := func(name string) *protocol.Service {
		if s, ok := byName[name]; ok {
			return s
		}
		s := &protocol.Service{Name: name, State: protocol.ServiceStopped}
		byName[name] = s
		order = append(order, name)
		return s
	}
	sc := bufio.NewScanner(bytes.NewReader(units))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:]
		}
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") || f[1] == "not-found" {
			continue
		}
		name := strings.TrimSuffix(f[0], ".service")
		if strings.HasSuffix(name, "@") || !protocol.ValidServiceName(name) {
			continue
		}
		s := add(name)
		switch f[2] {
		case "failed":
			s.State = protocol.ServiceFailed
		case "active":
			// Oneshot units that finished ("active exited") are not daemons.
			if f[3] == "running" {
				s.State = protocol.ServiceRunning
			}
		case "activating", "reloading":
			s.State = protocol.ServiceRunning
		}
	}
	sc = bufio.NewScanner(bytes.NewReader(files))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		name := strings.TrimSuffix(f[0], ".service")
		if strings.HasSuffix(name, "@") || !protocol.ValidServiceName(name) {
			continue
		}
		switch f[1] {
		case "enabled", "enabled-runtime":
			add(name).Enabled = true
		case "disabled", "masked", "masked-runtime", "indirect", "linked", "linked-runtime", "alias":
			add(name)
		}
	}
	out := make([]protocol.Service, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	return finishServices(out)
}

// parseOpenRC reads "rc-status --all": services listed under the boot,
// sysinit and default runlevels start at boot; "Dynamic Runlevel" sections
// (hotplugged, needed, manual) do not.
//
//	Runlevel: default
//	 sshd                     [  started  ]
//	Dynamic Runlevel: manual
//	 nginx                    [  stopped  ]
func parseOpenRC(status []byte) []protocol.Service {
	byName := map[string]*protocol.Service{}
	var order []string
	boot := false
	sc := bufio.NewScanner(bytes.NewReader(status))
	for sc.Scan() {
		line := sc.Text()
		if rl, ok := strings.CutPrefix(line, "Runlevel: "); ok {
			rl = strings.TrimSpace(rl)
			boot = rl == "default" || rl == "boot" || rl == "sysinit"
			continue
		}
		if strings.HasPrefix(line, "Dynamic Runlevel:") {
			boot = false
			continue
		}
		open, close := strings.IndexByte(line, '['), strings.LastIndexByte(line, ']')
		if open < 0 || close < open {
			continue
		}
		name := strings.TrimSpace(line[:open])
		state := strings.TrimSpace(line[open+1 : close])
		if !protocol.ValidServiceName(name) {
			continue
		}
		s, ok := byName[name]
		if !ok {
			s = &protocol.Service{Name: name}
			byName[name] = s
			order = append(order, name)
		}
		switch state {
		case "started", "starting":
			s.State = protocol.ServiceRunning
		case "crashed":
			s.State = protocol.ServiceFailed
		default:
			if s.State == "" {
				s.State = protocol.ServiceStopped
			}
		}
		s.Enabled = s.Enabled || boot
	}
	out := make([]protocol.Service, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	return finishServices(out)
}

func finishServices(s []protocol.Service) []protocol.Service {
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	if len(s) > protocol.MaxServices {
		s = s[:protocol.MaxServices]
	}
	return s
}
