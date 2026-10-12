package attackpath

import (
	"fmt"
	"strings"
)

// kindIcon maps hop kinds to ASCII markers (simple, minimal color).
var kindIcon = map[string]string{
	KindEntry:    "[ENTRY]   ",
	KindNetwork:  "[NETWORK] ",
	KindWorkload: "[WORKLOAD]",
	KindData:     "[DATA]    ",
	KindIdentity: "[IAM]     ",
}

// RenderASCII renders a chain as a human-readable ASCII diagram:
//
//	INTERNET
//	  │
//	  ▼
//	[ENTRY]    aws_lb.web — internet-facing load balancer (public entry point)
//	  │ evidence: internal = "false" (expected "true") @ main.tf:12
//	  ▼
//	[WORKLOAD] aws_instance.web — EC2 instance — reachable compute, potential stepping stone
//	  ...
func RenderASCII(c Chain) string {
	var sb strings.Builder
	sb.WriteString("INTERNET\n")
	for i, h := range c.Hops {
		sb.WriteString("  │\n")
		sb.WriteString("  ▼\n")
		icon := kindIcon[h.Kind]
		if icon == "" {
			icon = "[?]       "
		}
		fmt.Fprintf(&sb, "%s %s — %s\n", icon, h.Resource, h.Detail)
		ev := h.Evidence
		if ev.Attribute != "" {
			loc := ""
			if ev.Span.File != "" {
				loc = fmt.Sprintf(" @ %s:%d", ev.Span.File, ev.Span.StartLine)
			}
			fmt.Fprintf(&sb, "         │ evidence: %s = %q%s\n", ev.Attribute, ev.Actual, loc)
		}
		fmt.Fprintf(&sb, "         │ confidence: %s\n", h.Confidence)
		if h.Uncertain != "" {
			fmt.Fprintf(&sb, "         │ ⚠ %s\n", h.Uncertain)
		}
		_ = i
	}
	fmt.Fprintf(&sb, "\nChain confidence: %s", strings.ToUpper(c.Confidence))
	if c.Uncertain {
		sb.WriteString(" (contains uncertain hops — verify before acting)")
	}
	sb.WriteString("\n")
	return sb.String()
}

// RenderSummary returns a one-line chain summary for list views.
func RenderSummary(c Chain) string {
	parts := make([]string, 0, len(c.Hops)+1)
	parts = append(parts, "INTERNET")
	for _, h := range c.Hops {
		parts = append(parts, h.Resource)
	}
	s := strings.Join(parts, " → ")
	if c.Uncertain {
		s += " [UNCERTAIN]"
	}
	return s
}
