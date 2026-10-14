// Package rules — rule ID compatibility diagnostics.
//
// When rules are consolidated (see docs/audit/DEPRECATED_RULE_IDS.md),
// baselines and inline suppressions written against the old IDs must not
// silently stop matching. This file validates rule IDs found in baseline
// files and inline `aegis:skip` comments against the live registry and
// produces actionable diagnostics.
//
// Safety contract:
//   - A deprecated ID NEVER silently migrates to its canonical replacement.
//     Matching stays exact: a baseline entry for a removed ID simply does
//     not match new findings, and the user is told why.
//   - A suppression is NEVER silently discarded either: the diagnostic
//     tells the user the entry has no effect and how to migrate it.
//   - Diagnostics never include sensitive configuration values — only the
//     rule ID, the file it came from, and the migration pointer.
package rules

import (
	"fmt"
	"sort"

	"aegis/internal/ir"
)

// deprecatedRuleIDs maps rule IDs removed during the post-audit
// deduplication to their surviving canonical replacements.
// Source of truth: docs/audit/DEPRECATED_RULE_IDS.md (51 entries).
var deprecatedRuleIDs = map[string]string{
	"AEGIS-AWS-549":   "AEGIS-AWS-321",
	"AEGIS-AWS-550":   "AEGIS-AWS-320",
	"AEGIS-AWS-621":   "AEGIS-AWS-316",
	"AEGIS-AWS-684":   "AEGIS-AWS-565",
	"AEGIS-AWS-692":   "",
	"AEGIS-AWS-701":   "AEGIS-AWS-605",
	"AEGIS-AWS-702":   "AEGIS-AWS-546",
	"AEGIS-AWS-715":   "AEGIS-AWS-321",
	"AEGIS-AWS-718":   "AEGIS-AWS-608",
	"AEGIS-AWS-719":   "AEGIS-AWS-440",
	"AEGIS-AWS-752":   "AEGIS-AWS-625",
	"AEGIS-AWS-782":   "AEGIS-AWS-420",
	"AEGIS-AWS-815":   "AEGIS-AWS-430",
	"AEGIS-AWS-830":   "AEGIS-AWS-332",
	"AEGIS-AWS-831":   "AEGIS-AWS-404",
	"AEGIS-AZURE-036": "AEGIS-AZR-005",
	"AEGIS-AZURE-008": "AEGIS-AZURE-107",
	"AEGIS-AZURE-009": "AEGIS-AZURE-101",
	"AEGIS-AZURE-025": "AEGIS-AZURE-105",
	"AEGIS-AZURE-045": "AEGIS-AZURE-101",
	"AEGIS-AZURE-047": "AEGIS-AZURE-107",
	"AEGIS-AZURE-048": "AEGIS-AZURE-106",
	"AEGIS-AZURE-225": "AEGIS-AZURE-107",
	"AEGIS-AZURE-109": "AEGIS-AZURE-061",
	"AEGIS-AZURE-117": "AEGIS-AZURE-066",
	"AEGIS-AZURE-120": "AEGIS-AZURE-034",
	"AEGIS-AZURE-123": "AEGIS-AZURE-031",
	"AEGIS-AZURE-126": "AEGIS-AZURE-029",
	"AEGIS-AZURE-144": "AEGIS-AZURE-032",
	"AEGIS-AZURE-146": "AEGIS-AZURE-028",
	"AEGIS-AZURE-178": "AEGIS-AZURE-062",
	"AEGIS-AZURE-188": "AEGIS-AZURE-038",
	"AEGIS-AZURE-190": "AEGIS-AZURE-040",
	"AEGIS-AZURE-193": "AEGIS-AZURE-029",
	"AEGIS-AZURE-196": "AEGIS-AZURE-032",
	"AEGIS-AZURE-198": "AEGIS-AZURE-030",
	"AEGIS-AZURE-202": "AEGIS-AZURE-042",
	"AEGIS-AZURE-203": "AEGIS-AZURE-028",
	"AEGIS-AZURE-206": "AEGIS-AZURE-105",
	"AEGIS-AZURE-213": "AEGIS-AZURE-012",
	"AEGIS-AZURE-234": "AEGIS-AZURE-136",
	"AEGIS-AZURE-243": "AEGIS-AZURE-057",
	"AEGIS-AZURE-298": "AEGIS-AZURE-155",
	"AEGIS-AZURE-312": "AEGIS-AZURE-020",
	"AEGIS-AZR-004":   "AEGIS-AZURE-106",
	"AEGIS-GCP-063":   "AEGIS-GCP-018",
	"AEGIS-GCP-110":   "AEGIS-GCP-009",
	"AEGIS-GCP-112":   "AEGIS-GCP-011",
	"AEGIS-GCP-118":   "AEGIS-GCP-057",
	"AEGIS-GCP-119":   "AEGIS-GCP-058",
	"AEGIS-GCP-121":   "AEGIS-GCP-005",
	"AEGIS-GCP-122":   "AEGIS-GCP-032",
}

// RuleIDKind classifies a rule ID found in user configuration.
type RuleIDKind int

const (
	// RuleIDValid is a currently registered rule ID. No diagnostic.
	RuleIDValid RuleIDKind = iota
	// RuleIDDeprecated was removed by deduplication; a canonical
	// replacement is known. The entry has NO effect and must be migrated.
	RuleIDDeprecated
	// RuleIDUnknown is not registered and has no known replacement
	// (typo or a rule from another tool). The entry has NO effect.
	RuleIDUnknown
)

// RuleIDDiagnostic is one actionable warning about a rule ID found in a
// baseline file or inline suppression comment.
type RuleIDDiagnostic struct {
	// ID is the offending rule ID as written by the user.
	ID string
	// Kind distinguishes deprecated (migration known) from unknown (typo?).
	Kind RuleIDKind
	// Canonical is the replacement ID for deprecated IDs, else "".
	Canonical string
	// Source names where the ID was found, e.g. "baseline file" or
	// "inline suppression". Never contains config values.
	Source string
}

// Message renders the diagnostic as a single human-readable line.
func (d RuleIDDiagnostic) Message() string {
	switch d.Kind {
	case RuleIDDeprecated:
		if d.Canonical == "" {
			return fmt.Sprintf("rule ID %s in %s was removed and has no replacement; the entry has no effect (see docs/audit/DEPRECATED_RULE_IDS.md)",
				d.ID, d.Source)
		}
		return fmt.Sprintf("rule ID %s in %s was removed by deduplication and has no effect; migrate to %s (see docs/audit/DEPRECATED_RULE_IDS.md)",
			d.ID, d.Source, d.Canonical)
	default:
		return fmt.Sprintf("rule ID %s in %s is not a known Aegis rule and has no effect; check for a typo",
			d.ID, d.Source)
	}
}

// CheckRuleID classifies one rule ID against the registry. The magic
// "all" suppression ID is always valid.
func CheckRuleID(id string, reg *Registry) RuleIDKind {
	if id == suppressAll {
		return RuleIDValid
	}
	if reg != nil {
		for _, r := range reg.All() {
			if r.ID() == id {
				return RuleIDValid
			}
		}
	}
	if _, ok := deprecatedRuleIDs[id]; ok {
		return RuleIDDeprecated
	}
	return RuleIDUnknown
}

// CanonicalReplacement returns the surviving rule ID for a deprecated ID,
// or "" when the ID is not a known deprecated ID.
func CanonicalReplacement(id string) string {
	return deprecatedRuleIDs[id]
}

// ValidateBaselineIDs checks every rule ID in a loaded baseline against
// the registry. Returns one diagnostic per offending entry, sorted by ID
// for determinism. Valid IDs produce no diagnostics. A nil baseline or
// nil registry yields no diagnostics (fail-open: never block a scan on
// the check itself).
func ValidateBaselineIDs(b *Baseline, reg *Registry) []RuleIDDiagnostic {
	if b == nil || reg == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []RuleIDDiagnostic
	check := func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		kind := CheckRuleID(id, reg)
		if kind == RuleIDValid {
			return
		}
		out = append(out, RuleIDDiagnostic{
			ID:        id,
			Kind:      kind,
			Canonical: deprecatedRuleIDs[id],
			Source:    "baseline file",
		})
	}
	for _, fp := range b.Fingerprints {
		check(fp.RuleID)
	}
	for _, e := range b.Entries {
		check(e.RuleID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CollectSuppressedRuleIDs gathers every rule ID referenced by inline
// aegis:skip comments across the scanned resources, deduplicated and
// sorted for determinism.
func CollectSuppressedRuleIDs(resources []ir.Resource) []string {
	seen := map[string]bool{}
	for _, r := range resources {
		for _, id := range r.SuppressedRules {
			seen[id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ValidateSuppressedRuleIDs checks inline-suppression rule IDs against the
// registry. Returns one diagnostic per offending ID, sorted. Valid IDs
// (including "all") produce no diagnostics.
func ValidateSuppressedRuleIDs(ids []string, reg *Registry) []RuleIDDiagnostic {
	if reg == nil {
		return nil
	}
	var out []RuleIDDiagnostic
	for _, id := range ids {
		kind := CheckRuleID(id, reg)
		if kind == RuleIDValid {
			continue
		}
		out = append(out, RuleIDDiagnostic{
			ID:        id,
			Kind:      kind,
			Canonical: deprecatedRuleIDs[id],
			Source:    "inline suppression",
		})
	}
	return out
}
