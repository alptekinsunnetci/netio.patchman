package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"netio.patchman/internal/protocol"
)

// Live kernel patching: KernelCare (CloudLinux, AlmaLinux, Rocky, RHEL,
// Ubuntu, Debian) and Canonical Livepatch (Ubuntu) patch the running kernel
// without a reboot. The server uses the result for kernel findings, and a
// kernel update covered by KernelCare does not mark the host for a reboot.

var (
	kernelReleaseRE = regexp.MustCompile(`^[0-9]+\.[0-9]+[0-9A-Za-z._+~-]{0,100}$`)
	cveRE           = regexp.MustCompile(`(?i)\bcve-\d{4}-\d{4,7}\b`)
)

// kernelPatch reports the live patching service in use, or nil.
func kernelPatch(ctx context.Context) *protocol.KernelPatch {
	if _, err := exec.LookPath("kcarectl"); err == nil {
		out, _, err := run(ctx, time.Minute, "kcarectl", "--uname")
		if eff := strings.TrimSpace(string(out)); err == nil && kernelReleaseRE.MatchString(eff) {
			return &protocol.KernelPatch{Provider: protocol.KernelCare, EffectiveKernel: eff}
		}
	}
	if _, err := exec.LookPath("canonical-livepatch"); err == nil {
		out, _, err := run(ctx, time.Minute, "canonical-livepatch", "status", "--format", "json")
		if err == nil {
			return parseLivepatch(out)
		}
	}
	return nil
}

// parseLivepatch reads "canonical-livepatch status --format json". The patch
// list format changed between client versions, so CVE IDs are collected from
// the whole document once a patch state "applied" is present.
func parseLivepatch(out []byte) *protocol.KernelPatch {
	var doc any
	if json.Unmarshal(out, &doc) != nil || !hasAppliedState(doc) {
		return nil
	}
	kp := &protocol.KernelPatch{Provider: protocol.Livepatch}
	for _, m := range cveRE.FindAllString(string(out), -1) {
		id := strings.ToUpper(m)
		if !slices.Contains(kp.CVEs, id) && len(kp.CVEs) < 2000 {
			kp.CVEs = append(kp.CVEs, id)
		}
	}
	slices.Sort(kp.CVEs)
	return kp
}

func hasAppliedState(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && strings.EqualFold(k, "state") && strings.EqualFold(s, "applied") {
				return true
			}
			if hasAppliedState(val) {
				return true
			}
		}
	case []any:
		for _, val := range t {
			if hasAppliedState(val) {
				return true
			}
		}
	}
	return false
}

// rpmArches are the architecture suffixes of uname -r on RPM distributions.
var rpmArches = []string{".x86_64", ".aarch64", ".ppc64le", ".s390x", ".i686"}

// kernelCareCovers reports whether the KernelCare effective kernel is at least
// the newest installed kernel package, so a pending kernel update is already
// active through live patches.
func kernelCareCovers(effective, newestInstalled string) bool {
	if effective == "" || newestInstalled == "" {
		return false
	}
	trim := func(s string) string {
		for _, a := range rpmArches {
			s = strings.TrimSuffix(s, a)
		}
		return s
	}
	return rpmVerCmp(trim(effective), trim(newestInstalled)) >= 0
}

// rpmNonKernelReboot reports whether "needs-restarting -r" lists anything
// besides kernel packages (core libraries such as glibc or systemd).
func rpmNonKernelReboot(ctx context.Context) bool {
	if _, err := exec.LookPath("needs-restarting"); err != nil {
		return false
	}
	out, code, _ := run(ctx, 2*time.Minute, "needs-restarting", "-r")
	if code != 1 {
		return false
	}
	return len(nonKernelReasons(out)) > 0
}

// nonKernelReasons returns the "  * name" entries of needs-restarting -r that
// are not kernel packages.
func nonKernelReasons(out []byte) []string {
	var reasons []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		name, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "* ")
		if !ok || name == "" {
			continue
		}
		if rpmKernelPackages[name] || strings.HasPrefix(name, "kernel") || name == "linux-firmware" {
			continue
		}
		reasons = append(reasons, name)
	}
	return reasons
}

// rpmVerCmp compares two version-release strings like rpmvercmp: segments of
// digits compare numerically and are newer than letters, letters compare as
// strings, "~" sorts before everything.
func rpmVerCmp(a, b string) int {
	for a != "" || b != "" {
		if strings.HasPrefix(a, "~") || strings.HasPrefix(b, "~") {
			switch {
			case !strings.HasPrefix(a, "~"):
				return 1
			case !strings.HasPrefix(b, "~"):
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		a = strings.TrimLeftFunc(a, func(r rune) bool { return !isAlnum(r) && r != '~' })
		b = strings.TrimLeftFunc(b, func(r rune) bool { return !isAlnum(r) && r != '~' })
		if a == "" || b == "" {
			break
		}
		digit := unicode.IsDigit(rune(a[0]))
		segA, restA := segment(a, digit)
		segB, restB := segment(b, digit)
		if segB == "" {
			// Different segment types: numbers are newer.
			if digit {
				return 1
			}
			return -1
		}
		if digit {
			segA, segB = strings.TrimLeft(segA, "0"), strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				if len(segA) > len(segB) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
		a, b = restA, restB
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	default:
		return 1
	}
}

func isAlnum(r rune) bool { return r < 128 && (unicode.IsDigit(r) || unicode.IsLetter(r)) }

func segment(s string, digit bool) (string, string) {
	i := 0
	for i < len(s) && isAlnum(rune(s[i])) && unicode.IsDigit(rune(s[i])) == digit {
		i++
	}
	return s[:i], s[i:]
}
