// Package gcp implements the Aegis GCP security rule pack.
//
// Unknown-value contract (hard rule): an attribute that is present but
// unresolved (Value.Known == false, or a shape we cannot interpret) yields
// NO finding. Absent attributes are evaluated against the documented
// insecure default per rule. Rules never panic on unexpected shapes.
package gcp

import (
	"strings"

	"aegis/internal/ir"
)

// PackName identifies the GCP rule pack.
const PackName = "aegis-gcp"

// Rules returns every rule in the GCP pack, in ID order.
func Rules() []ir.Rule {
	rules := []ir.Rule{
		bucketPublicIAM{},         // AEGIS-GCP-001
		firewallOpenToWorld{},     // AEGIS-GCP-002
		sqlNoAutomatedBackups{},   // AEGIS-GCP-003
		gkeNoAuthorizedNetworks{}, // AEGIS-GCP-004
	}
	rules = append(rules, GCP2Rules()...) // AEGIS-GCP-005..024
	rules = append(rules, GCP3Rules()...) // AEGIS-GCP-025..100
	rules = append(rules, GCP4Rules()...) // AEGIS-GCP-101..122
	rules = append(rules, GCP5Rules()...) // AEGIS-GCP-123..142
	rules = append(rules, GCP6Rules()...) // AEGIS-GCP-143..182
	rules = append(rules, GCP7Rules()...) // AEGIS-GCP-183..222 (195 removed: subset of 006)
	rules = append(rules, GCP8Rules()...) // AEGIS-GCP-223..262
	return append(rules, GCP9Rules()...)  // AEGIS-GCP-263..292 (269/272/280/281/283/287 removed: dups)
}

// getString classifies a string attribute into a tri-state.
func getString(r ir.Resource, name string) (val string, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

// getStringList extracts a known list of strings; ok=false when the list
// is absent, unresolved, or contains non-string elements.
func getStringList(r ir.Resource, name string) ([]string, ir.Span, bool) {
	v, ok := r.Attributes[name]
	if !ok || !v.Known {
		return nil, ir.Span{}, false
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, v.Span, false
		}
		out = append(out, s)
	}
	return out, v.Span, true
}

// getBlocks returns nested blocks for an attribute: []Value of
// map[string]Value (a lone map is also accepted). present=false when the
// key is absent; known=false when unresolved or not a block shape.
func getBlocks(r ir.Resource, name string) (blks []map[string]ir.Value, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return nil, ir.Span{}, false, false
	}
	if !v.Known {
		return nil, v.Span, true, false
	}
	if m, ok := v.AsMap(); ok {
		return []map[string]ir.Value{m}, v.Span, true, true
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, true, false
	}
	out := make([]map[string]ir.Value, 0, len(l))
	for _, item := range l {
		m, ok := item.AsMap()
		if !ok {
			continue // unexpected shape: skip defensively
		}
		out = append(out, m)
	}
	return out, v.Span, true, true
}

// blockList extracts a nested block list from a block map.
func blockList(m map[string]ir.Value, name string) []map[string]ir.Value {
	v, ok := m[name]
	if !ok || !v.Known {
		return nil
	}
	if single, ok := v.AsMap(); ok {
		return []map[string]ir.Value{single}
	}
	l, ok := v.AsList()
	if !ok {
		return nil
	}
	out := make([]map[string]ir.Value, 0, len(l))
	for _, item := range l {
		if bm, ok := item.AsMap(); ok {
			out = append(out, bm)
		}
	}
	return out
}

// blockBool extracts a bool from a block map (tri-state).
func blockBool(m map[string]ir.Value, name string) (bool, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
}

// evidenceSpan prefers the attribute span, falling back to the resource span.
func evidenceSpan(attrSpan, resSpan ir.Span) ir.Span {
	if attrSpan.File != "" {
		return attrSpan
	}
	return resSpan
}

// mkFinding builds a finding with evidence.
func mkFinding(rule ir.Rule, r ir.Resource, attr string, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-001: GCS bucket publicly readable via IAM
// ---------------------------------------------------------------------------

type bucketPublicIAM struct{}

func (bucketPublicIAM) ID() string { return "AEGIS-GCP-001" }
func (bucketPublicIAM) Title() string {
	return "GCS bucket publicly readable via IAM"
}
func (bucketPublicIAM) Description() string {
	return "A bucket IAM binding/member granting objectViewer or admin to " +
		"allUsers or allAuthenticatedUsers exposes bucket data to the " +
		"internet."
}
func (bucketPublicIAM) Severity() ir.Severity { return ir.SeverityCritical }

func (bucketPublicIAM) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket_iam_binding" ||
		resType == "google_storage_bucket_iam_member"
}

// publicMembers are IAM member identities that mean "the internet".
func isPublicMember(m string) bool {
	m = strings.ToLower(strings.TrimSpace(m))
	return m == "allusers" || m == "allauthenticatedusers"
}

// broadReadRole reports whether the role grants broad read/admin on objects.
func isBroadReadRole(role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	return strings.Contains(role, "objectviewer") || strings.Contains(role, "admin")
}

func (s bucketPublicIAM) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil // role absent or unresolved: cannot decide
	}
	if !isBroadReadRole(role) {
		return nil
	}
	switch r.Type {
	case "google_storage_bucket_iam_binding":
		members, span, ok := getStringList(r, "members")
		if !ok {
			return nil // members absent or unresolved: cannot decide
		}
		for _, m := range members {
			if isPublicMember(m) {
				return []ir.Finding{mkFinding(s, r, "members", span,
					m, "remove allUsers/allAuthenticatedUsers from the binding")}
			}
		}
		return nil
	case "google_storage_bucket_iam_member":
		member, span, present, known := getString(r, "member")
		if !present || !known {
			return nil
		}
		if isPublicMember(member) {
			return []ir.Finding{mkFinding(s, r, "member", span,
				member, "remove allUsers/allAuthenticatedUsers from the member")}
		}
		return nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-002: Firewall open to the world
// ---------------------------------------------------------------------------

type firewallOpenToWorld struct{}

func (firewallOpenToWorld) ID() string { return "AEGIS-GCP-002" }
func (firewallOpenToWorld) Title() string {
	return "Firewall rule open to the world"
}
func (firewallOpenToWorld) Description() string {
	return "A compute firewall with source_ranges containing 0.0.0.0/0 and " +
		"an allow block permits traffic from the entire internet."
}
func (firewallOpenToWorld) Severity() ir.Severity { return ir.SeverityHigh }

func (firewallOpenToWorld) AppliesTo(resType string) bool {
	return resType == "google_compute_firewall"
}

func (s firewallOpenToWorld) Check(r ir.Resource) []ir.Finding {
	ranges, _, ok := getStringList(r, "source_ranges")
	if !ok {
		return nil // source_ranges absent or unresolved: cannot decide
	}
	open := false
	for _, sr := range ranges {
		if strings.TrimSpace(sr) == "0.0.0.0/0" {
			open = true
			break
		}
	}
	if !open {
		return nil
	}
	blks, span, present, known := getBlocks(r, "allow")
	if !present || !known || len(blks) == 0 {
		return nil // no allow block (or unresolved): cannot decide
	}
	return []ir.Finding{mkFinding(s, r, "source_ranges", span,
		"0.0.0.0/0 with allow block", "restricted source_ranges")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-003: Cloud SQL without automated backups
// ---------------------------------------------------------------------------

type sqlNoAutomatedBackups struct{}

func (sqlNoAutomatedBackups) ID() string { return "AEGIS-GCP-003" }
func (sqlNoAutomatedBackups) Title() string {
	return "Cloud SQL instance without automated backups"
}
func (sqlNoAutomatedBackups) Description() string {
	return "Cloud SQL instances should enable automated backups via " +
		"settings.backup_configuration.enabled for point-in-time recovery."
}
func (sqlNoAutomatedBackups) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlNoAutomatedBackups) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlNoAutomatedBackups) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := getBlocks(r, "settings")
	if !present {
		return nil // settings absent: cannot decide backup state
	}
	if !known {
		return nil // settings unresolved: cannot decide
	}
	for _, st := range settings {
		for _, bc := range blockList(st, "backup_configuration") {
			en, span, epresent, eknown := blockBool(bc, "enabled")
			if !epresent {
				continue // enabled absent in this block: keep looking
			}
			if !eknown {
				return nil // unresolved: cannot decide
			}
			if !en {
				return []ir.Finding{mkFinding(s, r,
					"settings.backup_configuration.enabled", span,
					"false", "settings { backup_configuration { enabled = true } }")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-004: GKE cluster without master authorized networks
// ---------------------------------------------------------------------------

type gkeNoAuthorizedNetworks struct{}

func (gkeNoAuthorizedNetworks) ID() string { return "AEGIS-GCP-004" }
func (gkeNoAuthorizedNetworks) Title() string {
	return "GKE cluster without master authorized networks"
}
func (gkeNoAuthorizedNetworks) Description() string {
	return "GKE clusters should restrict control-plane access with " +
		"master_authorized_networks_config. Without it, the API server " +
		"accepts connections from any IP."
}
func (gkeNoAuthorizedNetworks) Severity() ir.Severity { return ir.SeverityMedium }

func (gkeNoAuthorizedNetworks) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeNoAuthorizedNetworks) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBlocks(r, "master_authorized_networks_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		return nil // configured (any shape counts as an explicit choice)
	}
	return []ir.Finding{mkFinding(s, r, "master_authorized_networks_config", ir.Span{},
		"absent", "master_authorized_networks_config block restricting API access")}
}
