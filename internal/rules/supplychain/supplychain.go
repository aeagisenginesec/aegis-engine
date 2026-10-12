// Package supplychain implements Milestone 5 supply-chain advisory rules.
//
// CONTRACT (wired by the CLI, not this package): advisories arrive as
// synthetic IR resources:
//
//	ir.Resource{Type: "aegis_advisory", Name: advisory.ID, Provider: "aegis",
//	    Attributes: {"package": ..., "affected": ..., "severity": ...}}
//
// and provider version requirements as:
//
//	ir.Resource{Type: "terraform_provider", Name: source, Provider: "terraform",
//	    Attributes: {"version_constraint": ...}}
//
// Rule AEGIS-SC-001 fires when a pinned (concrete) provider version falls
// inside an advisory's affected range. A version_constraint that is not a
// concrete version (">= 5.0", "~> 4.2", "*", "var.x") yields NO finding:
// the scanner cannot decide, so it stays silent rather than guessing.
package supplychain

import (
	"fmt"
	"sort"
	"strings"

	"aegis/internal/advisories"
	"aegis/internal/ir"
)

// PackName identifies the supply-chain rule pack.
const PackName = "aegis-supplychain"

// Rules returns every rule in the supply-chain pack, in ID order.
func Rules() []ir.Rule {
	out := []ir.Rule{providerAdvisory{}}
	out = append(out, supplyChainExtraRules()...)
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-SC-001: provider version affected by known advisory
// ---------------------------------------------------------------------------

type providerAdvisory struct{}

func (providerAdvisory) ID() string    { return "AEGIS-SC-001" }
func (providerAdvisory) Title() string { return "Provider version affected by known advisory" }
func (providerAdvisory) Description() string {
	return "A pinned Terraform provider version falls inside the affected " +
		"range of a loaded supply-chain advisory (e.g. a CVE). Upgrade the " +
		"provider beyond the affected range. Range constraints that are not " +
		"concrete versions are not evaluated: the scanner cannot decide " +
		"whether they resolve to a vulnerable version."
}
func (providerAdvisory) Severity() ir.Severity { return ir.SeverityHigh }

// AppliesTo is consulted only for single-resource rules; the engine calls
// CheckAll for CrossResourceRule implementations. Kept truthful anyway.
func (providerAdvisory) AppliesTo(resType string) bool { return resType == "terraform_provider" }

// Check is a no-op: advisory matching needs the full resource set.
func (providerAdvisory) Check(ir.Resource) []ir.Finding { return nil }

func (providerAdvisory) CheckAll(resources []ir.Resource) []ir.Finding {
	var providers []ir.Resource
	var advs []advisory
	for _, r := range resources {
		switch r.Type {
		case "terraform_provider":
			providers = append(providers, r)
		case "aegis_advisory":
			if a, ok := advisoryFrom(r); ok {
				advs = append(advs, a)
			}
		}
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Address() < providers[j].Address() })
	sort.Slice(advs, func(i, j int) bool { return advs[i].id < advs[j].id })

	var out []ir.Finding
	for _, p := range providers {
		source := p.Name // contract: Name is the provider source, e.g. "hashicorp/aws"
		vc, ok := p.Attr("version_constraint")
		version, known := vc.AsString()
		if !ok || !known {
			continue // unknown version: cannot decide
		}
		version = strings.TrimSpace(version)
		if !advisories.IsConcreteVersion(version) {
			continue // range constraint, not a pinned version: cannot decide
		}
		for _, a := range advs {
			if a.pkg != source {
				continue // exact package match only
			}
			if !advisories.Affected(a.Advisory, version) {
				continue
			}
			span := p.Span
			if vc.Span.StartLine != 0 {
				span = vc.Span
			}
			out = append(out, ir.Finding{
				RuleID:      "AEGIS-SC-001",
				Title:       (providerAdvisory{}).Title(),
				Description: (providerAdvisory{}).Description(),
				Severity:    advisorySeverity(a.severity),
				Resource:    p.Address(),
				Evidence: ir.Evidence{
					Attribute: "version",
					Span:      span,
					Actual:    fmt.Sprintf("%s matches %s (%s)", version, a.id, a.affected),
					Expected:  "upgrade beyond the affected range",
				},
			})
		}
	}
	return out
}

// advisory is an advisories.Advisory with its resource identity attached.
type advisory struct {
	advisories.Advisory
	id       string
	pkg      string
	affected string
	severity string
}

// advisoryFrom decodes a synthetic aegis_advisory resource. Unknown or
// malformed fields make the advisory unusable -> ok=false (never match on
// garbage).
func advisoryFrom(r ir.Resource) (advisory, bool) {
	get := func(name string) (string, bool) {
		v, ok := r.Attr(name)
		if !ok {
			return "", false
		}
		return v.AsString()
	}
	pkg, ok1 := get("package")
	affected, ok2 := get("affected")
	severity, _ := get("severity") // optional: defaults to high
	if !ok1 || !ok2 || r.Name == "" || pkg == "" {
		return advisory{}, false
	}
	return advisory{
		Advisory: advisories.Advisory{ID: r.Name, Package: pkg, Affected: affected, Severity: severity},
		id:       r.Name,
		pkg:      pkg,
		affected: affected,
		severity: severity,
	}, true
}

// advisorySeverity maps an advisory severity string to ir.Severity.
// Unknown or empty values default to high.
func advisorySeverity(s string) ir.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return ir.SeverityCritical
	case "high":
		return ir.SeverityHigh
	case "medium":
		return ir.SeverityMedium
	case "low":
		return ir.SeverityLow
	case "info":
		return ir.SeverityInfo
	default:
		return ir.SeverityHigh
	}
}
