// Package advisories models supply-chain security advisories (e.g. CVEs
// against Terraform providers) and matches concrete versions against
// affected-version constraints.
//
// Constraint syntax (comma = AND):
//
//	">= 1.2.0", "<= 2.0.0", "> 1.0.0", "< 2.0.0", "= 1.2.3", "== 1.2.3",
//	"1.2.3" (bare version means equality),
//	"~> 4.2"   pessimistic: >= 4.2, < 5.0
//	"~> 4.2.1" pessimistic: >= 4.2.1, < 4.3
//
// Versions are compared numerically, part by part; missing parts are 0
// ("1.2" == "1.2.0"). Anything that is not a pure numeric dotted version,
// or any constraint part that does not parse, never matches: Affected
// returns false on garbage rather than guessing.
package advisories

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// Advisory is one supply-chain advisory against a package.
type Advisory struct {
	ID       string `json:"id"`       // e.g. "CVE-2024-1234"
	Package  string `json:"package"`  // e.g. "hashicorp/aws"
	Affected string `json:"affected"` // constraint, e.g. ">= 4.0.0, < 5.2.0"
	Severity string `json:"severity"` // "critical"|"high"|"medium"|"low"|"info"
}

// Load reads advisories from a JSON file: an array of Advisory objects.
func Load(path string) ([]Advisory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Advisory
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// IsConcreteVersion reports whether s is a plain numeric dotted version
// ("5.1.0"), as opposed to a range constraint (">= 5.0", "~> 4.2", "*").
func IsConcreteVersion(s string) bool {
	_, ok := parseVersion(s)
	return ok
}

// Affected reports whether a concrete version falls inside the advisory's
// affected range. An invalid version or an invalid/empty constraint never
// matches (returns false).
func Affected(a Advisory, version string) bool {
	v, ok := parseVersion(version)
	if !ok {
		return false
	}
	constraint := strings.TrimSpace(a.Affected)
	if constraint == "" {
		return false
	}
	for _, part := range strings.Split(constraint, ",") {
		if !matchPart(strings.TrimSpace(part), v) {
			return false
		}
	}
	return true
}

// matchPart evaluates one comma-separated constraint clause against v.
func matchPart(part string, v []int) bool {
	var op, vs string
	switch {
	case strings.HasPrefix(part, ">="):
		op, vs = ">=", strings.TrimSpace(part[2:])
	case strings.HasPrefix(part, "<="):
		op, vs = "<=", strings.TrimSpace(part[2:])
	case strings.HasPrefix(part, "~>"):
		op, vs = "~>", strings.TrimSpace(part[2:])
	case strings.HasPrefix(part, "=="):
		op, vs = "=", strings.TrimSpace(part[2:])
	case strings.HasPrefix(part, ">"):
		op, vs = ">", strings.TrimSpace(part[1:])
	case strings.HasPrefix(part, "<"):
		op, vs = "<", strings.TrimSpace(part[1:])
	case strings.HasPrefix(part, "="):
		op, vs = "=", strings.TrimSpace(part[1:])
	default:
		op, vs = "=", part
	}
	if op == "~>" {
		return matchPessimistic(vs, v)
	}
	cv, ok := parseVersion(vs)
	if !ok {
		return false
	}
	c := cmpVersion(v, cv)
	switch op {
	case ">=":
		return c >= 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case "<":
		return c < 0
	default: // "="
		return c == 0
	}
}

// matchPessimistic implements the "~>" operator: "~> 4.2" means >= 4.2, < 5.0
// and "~> 4.2.1" means >= 4.2.1, < 4.3 — the upper bound bumps the
// second-to-last specified part and drops everything after it.
func matchPessimistic(vs string, v []int) bool {
	lo, ok := parseVersion(vs)
	if !ok {
		return false
	}
	hi := make([]int, len(lo))
	copy(hi, lo)
	if len(hi) == 1 {
		hi[0]++
	} else {
		hi[len(hi)-2]++
		hi = hi[:len(hi)-1]
	}
	return cmpVersion(v, lo) >= 0 && cmpVersion(v, hi) < 0
}

// parseVersion parses a strict numeric dotted version ("5.1.0"). Missing
// parts are treated as 0 by cmpVersion. Anything else fails.
func parseVersion(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// cmpVersion compares two versions numerically, treating missing parts as 0.
func cmpVersion(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}
