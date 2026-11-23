// Package pkgver compares package versions the way the distribution's
// package manager does: dpkg (Debian, Ubuntu), rpm (RHEL family, SUSE) and
// apk (Alpine). Distribution versions carry backported fixes in their
// revision ("1.22.1-9+deb12u3", "1.20.1-14.el9_2.1"), so policy checks must
// compare full package versions with these rules, never upstream numbers.
package pkgver

import (
	"strings"

	"netio.patchman/internal/protocol"
)

// Compare returns -1, 0 or 1 comparing a and b with the rules of the
// package manager pm (apt, dnf, yum, zypper, apk). Unknown managers use the
// rpm rules, which order plain dotted versions sensibly.
func Compare(pm, a, b string) int {
	switch pm {
	case protocol.PMApt:
		return CompareDeb(a, b)
	case protocol.PMApk:
		return CompareAPK(a, b)
	}
	return CompareRPM(a, b)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// ---------- dpkg ----------

// splitDeb splits [epoch:]upstream[-revision].
func splitDeb(v string) (epoch, upstream, revision string) {
	v = strings.TrimSpace(v)
	if e, rest, ok := strings.Cut(v, ":"); ok && isDigits(e) {
		epoch, v = e, rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// CompareDeb implements dpkg's version comparison (deb-version(7)).
func CompareDeb(a, b string) int {
	ea, ua, ra := splitDeb(a)
	eb, ub, rb := splitDeb(b)
	if c := compareNum(ea, eb); c != 0 {
		return c
	}
	if c := debPart(ua, ub); c != 0 {
		return c
	}
	return debPart(ra, rb)
}

// debOrder gives the sort weight of a character in a non-digit run:
// "~" sorts before everything, even the end of the part, letters before
// non-letters.
func debOrder(c byte, end bool) int {
	switch {
	case end:
		return 0
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	}
	return int(c) + 256
}

func debPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Non-digit prefix.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac := debOrder(byteAt(a, i), i >= len(a))
			bc := debOrder(byteAt(b, j), j >= len(b))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		// Digit run.
		si := i
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		sj := j
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := compareNum(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// compareNum compares digit strings of any length numerically ("" = 0).
func compareNum(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return sign(strings.Compare(a, b))
}

// ---------- rpm ----------

// splitRPM splits [epoch:]version[-release]; a missing epoch is 0.
func splitRPM(v string) (epoch, version, release string) {
	v = strings.TrimSpace(v)
	if e, rest, ok := strings.Cut(v, ":"); ok && isDigits(e) {
		epoch, v = e, rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// CompareRPM implements rpm's EVR comparison (rpmvercmp per field). A
// release is only compared when both versions have one, as rpm does for
// dependency checks ("1.2" matches every "1.2-x").
func CompareRPM(a, b string) int {
	ea, va, ra := splitRPM(a)
	eb, vb, rb := splitRPM(b)
	if c := compareNum(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	if ra == "" || rb == "" {
		return 0
	}
	return rpmvercmp(ra, rb)
}

// rpmvercmp is rpm's segment comparison: alphanumeric segments, separators
// ignored, "~" sorts before anything, "^" after the base but before more.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// Tilde: older than anything, including the end.
		if byteAt(a, i) == '~' || byteAt(b, j) == '~' {
			if byteAt(a, i) != '~' {
				return 1
			}
			if byteAt(b, j) != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		// Caret: newer than the end, older than another segment.
		if byteAt(a, i) == '^' || byteAt(b, j) == '^' {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if byteAt(a, i) != '^' {
				return 1
			}
			if byteAt(b, j) != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		sa, sb := a[si:i], b[sj:j]
		if sb == "" {
			// Different segment types: numeric is newer.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			if c := compareNum(sa, sb); c != 0 {
				return c
			}
		} else if c := strings.Compare(sa, sb); c != 0 {
			return sign(c)
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// ---------- apk ----------

// apkSuffix orders the pre- and post-release suffixes of apk versions.
var apkSuffix = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

type apkVersion struct {
	nums     []string
	letter   byte
	suffixes [][2]string // name, number
	rev      string
}

func parseAPK(v string) apkVersion {
	var out apkVersion
	v = strings.TrimSpace(v)
	if i := strings.LastIndex(v, "-r"); i >= 0 && isDigits(v[i+2:]) {
		out.rev, v = v[i+2:], v[:i]
	}
	main, rest, _ := strings.Cut(v, "_")
	if n := len(main); n > 0 && isAlpha(main[n-1]) {
		out.letter, main = main[n-1], main[:n-1]
	}
	out.nums = strings.Split(main, ".")
	if rest != "" {
		for _, s := range strings.Split(rest, "_") {
			k := 0
			for k < len(s) && isAlpha(s[k]) {
				k++
			}
			out.suffixes = append(out.suffixes, [2]string{s[:k], s[k:]})
		}
	}
	return out
}

// CompareAPK implements apk-tools' version ordering for the common forms
// (1.2.3, 1.2.3a, 1.2.3_rc1, 1.2.3_p2-r1).
func CompareAPK(a, b string) int {
	va, vb := parseAPK(a), parseAPK(b)
	for k := 0; k < max(len(va.nums), len(vb.nums)); k++ {
		if k >= len(va.nums) {
			return -1
		}
		if k >= len(vb.nums) {
			return 1
		}
		if c := compareNum(va.nums[k], vb.nums[k]); c != 0 {
			return c
		}
	}
	if va.letter != vb.letter {
		return sign(int(va.letter) - int(vb.letter))
	}
	for k := 0; k < max(len(va.suffixes), len(vb.suffixes)); k++ {
		var sa, sb [2]string
		if k < len(va.suffixes) {
			sa = va.suffixes[k]
		}
		if k < len(vb.suffixes) {
			sb = vb.suffixes[k]
		}
		if c := sign(apkSuffix[sa[0]] - apkSuffix[sb[0]]); c != 0 {
			return c
		}
		if c := compareNum(sa[1], sb[1]); c != 0 {
			return c
		}
	}
	return compareNum(va.rev, vb.rev)
}

// Upstream returns the upstream part of a distribution version: without the
// epoch and the package revision ("1:2.4.57-5+deb12u1" -> "2.4.57").
func Upstream(pm, v string) string {
	v = strings.TrimSpace(v)
	switch pm {
	case protocol.PMApk:
		if i := strings.LastIndex(v, "-r"); i >= 0 && isDigits(v[i+2:]) {
			v = v[:i]
		}
		return v
	case protocol.PMApt:
		_, u, _ := splitDeb(v)
		// Debian repacks: "1.2.3+dfsg", "1.2.3~rc1+ds".
		return u
	}
	_, u, _ := splitRPM(v)
	return u
}

// MajorMinor returns the first two numeric components of an upstream
// version ("8.2.7" -> "8.2", "16.4" -> "16.4", "2.4" -> "2.4"); with one
// component only that one ("16" -> "16").
func MajorMinor(upstream string) string {
	var parts []string
	start := -1
	for i := 0; i <= len(upstream); i++ {
		if i < len(upstream) && isDigit(upstream[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			parts = append(parts, strings.TrimLeft(upstream[start:i], "0"))
			if parts[len(parts)-1] == "" {
				parts[len(parts)-1] = "0"
			}
			start = -1
			if len(parts) == 2 {
				break
			}
		}
		// Only dots separate the components ("8.9p1" stops at "p").
		if i >= len(upstream) || upstream[i] != '.' || len(parts) == 0 {
			break
		}
	}
	return strings.Join(parts, ".")
}

// Major returns the first numeric component ("16.4" -> "16").
func Major(upstream string) string {
	mm := MajorMinor(upstream)
	m, _, _ := strings.Cut(mm, ".")
	return m
}
