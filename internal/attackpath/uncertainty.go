package attackpath

import (
	"strings"

	"aegis/internal/ir"
)

// uncertaintyReasons are the explicit markers used when a hop cannot be
// proven. Every uncertain hop MUST carry one of these (or a specific
// variant) — never a vague "maybe".
const (
	UncertainVariable   = "UNCERTAIN: value comes from a variable — actual value unknown at scan time"
	UncertainCount      = "UNCERTAIN: resource uses count/for_each — instance set unknown at scan time"
	UncertainDynamic    = "UNCERTAIN: dynamic block — expanded content unknown at scan time"
	UncertainDataSource = "UNCERTAIN: value comes from a data source — resolved only at apply time"
	UncertainCondition  = "UNCERTAIN: conditional expression — branch taken unknown at scan time"
	UncertainReference  = "UNCERTAIN: reference target not found in configuration"
	UncertainDefault    = "UNCERTAIN: relying on provider default — verify in plan output"
)

// refPrefixes that indicate an unresolvable-at-scan-time value.
var unresolvablePrefixes = []string{
	"var.", "local.", "data.", "each.", "count.", "self.",
	"module.", "terraform.", "path.",
}

// ClassifyUncertainty examines an ir.Value and returns the uncertainty
// reason, or "" if the value is concrete and provable.
func ClassifyUncertainty(v ir.Value) string {
	// Check the raw text and Ref first: even unknown values may carry a
	// reference string that tells us WHY it's unknown (var., data., etc.).
	// This must come before the Known check.
	candidates := []string{}
	if s, ok := v.Raw.(string); ok {
		candidates = append(candidates, strings.TrimSpace(s))
	}
	if v.Ref != "" {
		candidates = append(candidates, strings.TrimSpace(v.Ref))
	}
	for _, raw := range candidates {
		if raw == "" {
			continue
		}
		if reason := classifyString(raw); reason != "" {
			return reason
		}
	}
	// List values: inspect items (e.g. [var.allowed_cidr]).
	if l, ok := v.Raw.([]ir.Value); ok {
		for _, item := range l {
			if reason := ClassifyUncertainty(item); reason != "" {
				return reason
			}
		}
	}
	if !v.Known {
		return UncertainCondition
	}
	return ""
}

// classifyString returns the uncertainty reason for a raw string value,
// or "" if the string is concrete.
func classifyString(raw string) string {
	for _, p := range unresolvablePrefixes {
		if strings.HasPrefix(raw, p) {
			switch {
			case strings.HasPrefix(raw, "var."), strings.HasPrefix(raw, "local."):
				return UncertainVariable
			case strings.HasPrefix(raw, "data."):
				return UncertainDataSource
			case strings.HasPrefix(raw, "each."), strings.HasPrefix(raw, "count."):
				return UncertainCount
			default:
				return UncertainReference
			}
		}
	}
	// Conditional expressions: condition ? a : b
	if strings.Contains(raw, "?") && strings.Contains(raw, ":") {
		return UncertainCondition
	}
	return ""
}

// HopConfidence derives hop confidence from the evidence value:
// concrete literals → high, resolvable refs → medium, uncertain → low.
func HopConfidence(v ir.Value) string {
	if u := ClassifyUncertainty(v); u != "" {
		return ConfidenceLow
	}
	s, _ := v.Raw.(string)
	raw := strings.TrimSpace(s)
	// IP addresses, CIDRs, and quoted strings are concrete literals,
	// even though they contain dots.
	trimmed := strings.Trim(raw, `"`)
	if isIPOrCIDR(trimmed) || strings.HasPrefix(raw, `"`) {
		return ConfidenceHigh
	}
	// A bare reference to another resource (aws_sg.web.id) is medium:
	// resolvable, but indirection adds risk.
	if strings.Contains(raw, ".") {
		return ConfidenceMedium
	}
	return ConfidenceHigh
}

// isIPOrCIDR reports whether s looks like an IP address or CIDR block.
func isIPOrCIDR(s string) bool {
	// Strip CIDR suffix.
	base := s
	if i := strings.Index(s, "/"); i >= 0 {
		base = s[:i]
	}
	parts := strings.Split(base, ".")
	if len(parts) == 4 {
		allNum := true
		for _, p := range parts {
			if p == "" {
				allNum = false
				break
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					allNum = false
					break
				}
			}
		}
		if allNum {
			return true
		}
	}
	// IPv6 contains colons.
	return strings.Contains(s, ":")
}

// MarkUncertain annotates a hop with an explicit uncertainty reason and
// drops its confidence to low. The hop is still reported — the uncertainty
// is the finding, not a reason to hide it.
func MarkUncertain(h *Hop, reason string) {
	h.Uncertain = reason
	h.Confidence = ConfidenceLow
}
