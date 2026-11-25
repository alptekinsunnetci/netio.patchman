package version

import (
	"strconv"
	"strings"
)

// Compare compares two versions numerically ("0.10.0" > "0.9.1"). A
// pre-release ("0.2.0-dev") sorts before its release ("0.2.0").
func Compare(a, b string) int {
	an, ap, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	bn, bp, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	as, bs := strings.Split(an, "."), strings.Split(bn, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		x, y := 0, 0
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	return strings.Compare(ap, bp)
}
