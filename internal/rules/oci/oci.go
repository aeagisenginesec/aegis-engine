// Package oci implements the Aegis Oracle Cloud Infrastructure rule pack.
//
// Unknown-value contract (hard rule): an attribute that is present but
// unresolved (Value.Known == false, or a shape we cannot interpret) yields
// NO finding. Absent attributes are evaluated against the documented
// insecure default per rule. Rules never panic on unexpected shapes.
package oci

import (
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// PackName identifies the OCI rule pack.
const PackName = "aegis-oci"

// Rules returns every rule in the OCI pack, in ID order.
func Rules() []ir.Rule {
	return []ir.Rule{
		bucketNoKMS{},        // AEGIS-OCI-001
		bucketPublicAccess{}, // AEGIS-OCI-002
		seclistOpenIngress{}, // AEGIS-OCI-003
		policyWildcard{},     // AEGIS-OCI-004
		volumeNoKMS{},        // AEGIS-OCI-005
		adbNoKMS{},           // AEGIS-OCI-006
		cloudGuardOff{},      // AEGIS-OCI-007
		logShortRetention{},  // AEGIS-OCI-008
	}
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

// getNum classifies a numeric attribute into a tri-state.
func getNum(r ir.Resource, name string) (val float64, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return 0, ir.Span{}, false, false
	}
	if !v.Known {
		return 0, v.Span, true, false
	}
	f, ok := v.Raw.(float64)
	return f, v.Span, true, ok
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

// blockString extracts a string from a block map (tri-state).
func blockString(m map[string]ir.Value, name string) (string, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
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
// AEGIS-OCI-001: Object Storage bucket without KMS encryption
// ---------------------------------------------------------------------------

type bucketNoKMS struct{}

func (bucketNoKMS) ID() string { return "AEGIS-OCI-001" }
func (bucketNoKMS) Title() string {
	return "Object Storage bucket without KMS encryption"
}
func (bucketNoKMS) Description() string {
	return "oci_objectstorage_bucket without kms_key_id relies on " +
		"Oracle-managed encryption keys. Assign a customer-managed Vault " +
		"key so you control key rotation and revocation."
}
func (bucketNoKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (bucketNoKMS) AppliesTo(resType string) bool {
	return resType == "oci_objectstorage_bucket"
}

func (s bucketNoKMS) Check(r ir.Resource) []ir.Finding {
	key, span, present, known := getString(r, "kms_key_id")
	if present && !known {
		return nil
	}
	if present && strings.TrimSpace(key) != "" {
		return nil
	}
	actual := "absent (Oracle-managed keys)"
	if present {
		actual = "empty kms_key_id"
	}
	return []ir.Finding{mkFinding(s, r, "kms_key_id",
		evidenceSpan(span, r.Span), actual,
		"kms_key_id = \"<vault-key-ocid>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-002: Object Storage bucket with public access
// ---------------------------------------------------------------------------

type bucketPublicAccess struct{}

func (bucketPublicAccess) ID() string { return "AEGIS-OCI-002" }
func (bucketPublicAccess) Title() string {
	return "Object Storage bucket with public access"
}
func (bucketPublicAccess) Description() string {
	return "oci_objectstorage_bucket with access_type ObjectRead or " +
		"ObjectReadWithoutList exposes bucket objects to the internet " +
		"without authentication. Keep access_type at NoPublicAccess."
}
func (bucketPublicAccess) Severity() ir.Severity { return ir.SeverityCritical }

func (bucketPublicAccess) AppliesTo(resType string) bool {
	return resType == "oci_objectstorage_bucket"
}

func (s bucketPublicAccess) Check(r ir.Resource) []ir.Finding {
	at, span, present, known := getString(r, "access_type")
	if !present || !known {
		return nil // default is NoPublicAccess; unresolved: cannot decide
	}
	a := strings.ToLower(strings.TrimSpace(at))
	if a == "objectread" || a == "objectreadwithoutlist" {
		return []ir.Finding{mkFinding(s, r, "access_type", span, at,
			"access_type = \"NoPublicAccess\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-003: VCN security list with open ingress
// ---------------------------------------------------------------------------

type seclistOpenIngress struct{}

func (seclistOpenIngress) ID() string { return "AEGIS-OCI-003" }
func (seclistOpenIngress) Title() string {
	return "VCN security list with open ingress"
}
func (seclistOpenIngress) Description() string {
	return "oci_core_security_list with an ingress_security_rules entry " +
		"sourcing 0.0.0.0/0 permits traffic from the entire internet into " +
		"the subnet. Restrict ingress sources to known CIDRs."
}
func (seclistOpenIngress) Severity() ir.Severity { return ir.SeverityHigh }

func (seclistOpenIngress) AppliesTo(resType string) bool {
	return resType == "oci_core_security_list"
}

func (s seclistOpenIngress) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "ingress_security_rules")
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for _, b := range blks {
		src, sspan, spresent, sknown := blockString(b, "source")
		if !spresent || !sknown {
			continue
		}
		if strings.TrimSpace(src) != "0.0.0.0/0" {
			continue
		}
		proto, _, _, _ := blockString(b, "protocol")
		actual := "0.0.0.0/0"
		if proto != "" {
			actual = "0.0.0.0/0 (protocol " + proto + ")"
		}
		out = append(out, mkFinding(s, r, "ingress_security_rules",
			evidenceSpan(sspan, evidenceSpan(span, r.Span)), actual,
			"restrict source to known CIDRs"))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-004: IAM policy with wildcard manage permissions
// ---------------------------------------------------------------------------

type policyWildcard struct{}

func (policyWildcard) ID() string { return "AEGIS-OCI-004" }
func (policyWildcard) Title() string {
	return "IAM policy with wildcard manage permissions"
}
func (policyWildcard) Description() string {
	return "oci_identity_policy with a statement like \"Allow group ... to " +
		"manage all-resources in tenancy\" grants full administrative power " +
		"over every resource, violating least privilege. Scope statements " +
		"to the resource types and compartments the group needs."
}
func (policyWildcard) Severity() ir.Severity { return ir.SeverityCritical }

func (policyWildcard) AppliesTo(resType string) bool {
	return resType == "oci_identity_policy"
}

// isWildcardManage reports whether a policy statement grants manage over
// all resource types.
func isWildcardManage(stmt string) bool {
	flat := strings.ToLower(stmt)
	flat = strings.Join(strings.Fields(flat), " ")
	return strings.Contains(flat, "manage all-resources")
}

func (s policyWildcard) Check(r ir.Resource) []ir.Finding {
	stmts, span, ok := getStringList(r, "statements")
	if !ok {
		return nil // absent or unresolved: cannot decide
	}
	var out []ir.Finding
	for _, st := range stmts {
		if !isWildcardManage(st) {
			continue
		}
		out = append(out, mkFinding(s, r, "statements", span,
			"statement grants \"manage all-resources\"",
			"scope verbs to specific resource types, e.g. \"manage instances\""))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-005: Block volume without KMS encryption
// ---------------------------------------------------------------------------

type volumeNoKMS struct{}

func (volumeNoKMS) ID() string { return "AEGIS-OCI-005" }
func (volumeNoKMS) Title() string {
	return "Block volume without KMS encryption"
}
func (volumeNoKMS) Description() string {
	return "oci_core_volume without kms_key_id relies on Oracle-managed " +
		"keys. Boot volumes and data volumes are block volumes: assign a " +
		"customer-managed Vault key so you control encryption and " +
		"revocation."
}
func (volumeNoKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (volumeNoKMS) AppliesTo(resType string) bool {
	return resType == "oci_core_volume"
}

func (s volumeNoKMS) Check(r ir.Resource) []ir.Finding {
	key, span, present, known := getString(r, "kms_key_id")
	if present && !known {
		return nil
	}
	if present && strings.TrimSpace(key) != "" {
		return nil
	}
	actual := "absent (Oracle-managed keys)"
	if present {
		actual = "empty kms_key_id"
	}
	return []ir.Finding{mkFinding(s, r, "kms_key_id",
		evidenceSpan(span, r.Span), actual,
		"kms_key_id = \"<vault-key-ocid>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-006: Autonomous Database without KMS encryption
// ---------------------------------------------------------------------------

type adbNoKMS struct{}

func (adbNoKMS) ID() string { return "AEGIS-OCI-006" }
func (adbNoKMS) Title() string {
	return "Autonomous Database without customer-managed encryption"
}
func (adbNoKMS) Description() string {
	return "oci_database_autonomous_database without kms_key_id relies on " +
		"Oracle-managed encryption. Assign a customer-managed Vault key " +
		"for control over key rotation and revocation."
}
func (adbNoKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (adbNoKMS) AppliesTo(resType string) bool {
	return resType == "oci_database_autonomous_database"
}

func (s adbNoKMS) Check(r ir.Resource) []ir.Finding {
	key, span, present, known := getString(r, "kms_key_id")
	if present && !known {
		return nil
	}
	if present && strings.TrimSpace(key) != "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "kms_key_id",
		evidenceSpan(span, r.Span), "absent (Oracle-managed keys)",
		"kms_key_id = \"<vault-key-ocid>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-007: Cloud Guard not enabled
// ---------------------------------------------------------------------------

type cloudGuardOff struct{}

func (cloudGuardOff) ID() string { return "AEGIS-OCI-007" }
func (cloudGuardOff) Title() string {
	return "Cloud Guard not enabled"
}
func (cloudGuardOff) Description() string {
	return "oci_cloud_guard_cloud_guard_configuration without status = " +
		"\"ENABLED\" leaves the tenancy without Cloud Guard threat " +
		"detection and responder rules. Enable Cloud Guard with a reporting " +
		"region."
}
func (cloudGuardOff) Severity() ir.Severity { return ir.SeverityHigh }

func (cloudGuardOff) AppliesTo(resType string) bool {
	return resType == "oci_cloud_guard_cloud_guard_configuration"
}

func (s cloudGuardOff) Check(r ir.Resource) []ir.Finding {
	status, span, present, known := getString(r, "status")
	if present && !known {
		return nil
	}
	if present && strings.EqualFold(strings.TrimSpace(status), "ENABLED") {
		return nil
	}
	actual := "absent (not enabled)"
	if present {
		actual = status
	}
	return []ir.Finding{mkFinding(s, r, "status",
		evidenceSpan(span, r.Span), actual, "status = \"ENABLED\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-008: Logging log with short retention
// ---------------------------------------------------------------------------

type logShortRetention struct{}

func (logShortRetention) ID() string { return "AEGIS-OCI-008" }
func (logShortRetention) Title() string {
	return "Logging log with short retention"
}
func (logShortRetention) Description() string {
	return "oci_logging_log with retention_period absent (provider default " +
		"30 days) or below 90 days discards audit and service logs before " +
		"investigations finish. Retain logs at least 90 days."
}
func (logShortRetention) Severity() ir.Severity { return ir.SeverityMedium }

func (logShortRetention) AppliesTo(resType string) bool {
	return resType == "oci_logging_log"
}

func (s logShortRetention) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNum(r, "retention_period")
	if present && !known {
		return nil
	}
	if present && days >= 90 {
		return nil
	}
	actual := "absent (provider default: 30 days)"
	if present {
		actual = fmt.Sprintf("%g days", days)
	}
	return []ir.Finding{mkFinding(s, r, "retention_period",
		evidenceSpan(span, r.Span), actual, "retention_period >= 90")}
}
