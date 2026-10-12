// Package alibaba implements the Aegis Alibaba Cloud rule pack.
//
// Unknown-value contract (hard rule): an attribute that is present but
// unresolved (Value.Known == false, or a shape we cannot interpret) yields
// NO finding. Absent attributes are evaluated against the documented
// insecure default per rule. Rules never panic on unexpected shapes.
package alibaba

import (
	"strings"

	"aegis/internal/ir"
)

// PackName identifies the Alibaba Cloud rule pack.
const PackName = "aegis-alibaba"

// Rules returns every rule in the Alibaba Cloud pack, in ID order.
func Rules() []ir.Rule {
	rules := []ir.Rule{
		ossNoEncryption{},       // AEGIS-ALI-001
		ossPublicACL{},          // AEGIS-ALI-002
		ossNoVersioning{},       // AEGIS-ALI-003
		ossNoLogging{},          // AEGIS-ALI-004
		ramWeakPasswordPolicy{}, // AEGIS-ALI-005
		ramLoginNoMFA{},         // AEGIS-ALI-006
	}
	return append(rules, Alibaba2Rules()...) // AEGIS-ALI-007..012
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

// getBool classifies a bool attribute into a tri-state.
func getBool(r ir.Resource, name string) (val bool, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
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

// blockBool extracts a bool from a block map (tri-state).
func blockBool(m map[string]ir.Value, name string) (bool, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
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
// AEGIS-ALI-001: OSS bucket without server-side encryption
// ---------------------------------------------------------------------------

type ossNoEncryption struct{}

func (ossNoEncryption) ID() string { return "AEGIS-ALI-001" }
func (ossNoEncryption) Title() string {
	return "OSS bucket without server-side encryption"
}
func (ossNoEncryption) Description() string {
	return "alicloud_oss_bucket without a server_side_encryption_rule block " +
		"stores objects unencrypted at rest. Enable SSE-OSS or SSE-KMS so " +
		"bucket data is encrypted with Alibaba Cloud managed keys."
}
func (ossNoEncryption) Severity() ir.Severity { return ir.SeverityHigh }

func (ossNoEncryption) AppliesTo(resType string) bool {
	return resType == "alicloud_oss_bucket"
}

func (s ossNoEncryption) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "server_side_encryption_rule")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	actual := "absent (no server-side encryption)"
	if present {
		actual = "empty server_side_encryption_rule block"
	}
	return []ir.Finding{mkFinding(s, r, "server_side_encryption_rule",
		evidenceSpan(span, r.Span), actual,
		"server_side_encryption_rule { sse_algorithm = \"AES256\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-002: OSS bucket with public ACL / public access not blocked
// ---------------------------------------------------------------------------

type ossPublicACL struct{}

func (ossPublicACL) ID() string { return "AEGIS-ALI-002" }
func (ossPublicACL) Title() string {
	return "OSS bucket publicly accessible"
}
func (ossPublicACL) Description() string {
	return "An OSS bucket with acl set to public-read or public-read-write " +
		"exposes its objects to the internet, and an " +
		"alicloud_oss_bucket_public_access_block with block_public_acls = " +
		"false leaves the bucket open to public ACLs. Keep buckets private " +
		"and block public access."
}
func (ossPublicACL) Severity() ir.Severity { return ir.SeverityCritical }

func (ossPublicACL) AppliesTo(resType string) bool {
	return resType == "alicloud_oss_bucket" ||
		resType == "alicloud_oss_bucket_public_access_block"
}

func (s ossPublicACL) Check(r ir.Resource) []ir.Finding {
	switch r.Type {
	case "alicloud_oss_bucket":
		acl, span, present, known := getString(r, "acl")
		if !present || !known {
			return nil // default is private; unresolved: cannot decide
		}
		a := strings.ToLower(strings.TrimSpace(acl))
		if a == "public-read" || a == "public-read-write" {
			return []ir.Finding{mkFinding(s, r, "acl", span, acl,
				"acl = \"private\"")}
		}
		return nil
	case "alicloud_oss_bucket_public_access_block":
		blocked, span, present, known := getBool(r, "block_public_acls")
		if !present || !known {
			return nil
		}
		if !blocked {
			return []ir.Finding{mkFinding(s, r, "block_public_acls", span,
				"false", "block_public_acls = true")}
		}
		return nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-003: OSS bucket without versioning
// ---------------------------------------------------------------------------

type ossNoVersioning struct{}

func (ossNoVersioning) ID() string { return "AEGIS-ALI-003" }
func (ossNoVersioning) Title() string {
	return "OSS bucket without versioning"
}
func (ossNoVersioning) Description() string {
	return "alicloud_oss_bucket without a versioning block (or with status " +
		"other than Enabled) cannot recover objects from accidental deletion " +
		"or overwrite. Enable versioning for data resilience."
}
func (ossNoVersioning) Severity() ir.Severity { return ir.SeverityMedium }

func (ossNoVersioning) AppliesTo(resType string) bool {
	return resType == "alicloud_oss_bucket"
}

func (s ossNoVersioning) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "versioning")
	if present && !known {
		return nil
	}
	if present {
		for _, b := range blks {
			status, _, _, ok := blockString(b, "status")
			if ok && strings.EqualFold(strings.TrimSpace(status), "Enabled") {
				return nil
			}
		}
	}
	actual := "absent (versioning disabled)"
	if present {
		actual = "versioning block without status = \"Enabled\""
	}
	return []ir.Finding{mkFinding(s, r, "versioning",
		evidenceSpan(span, r.Span), actual,
		"versioning { status = \"Enabled\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-004: OSS bucket without access logging
// ---------------------------------------------------------------------------

type ossNoLogging struct{}

func (ossNoLogging) ID() string { return "AEGIS-ALI-004" }
func (ossNoLogging) Title() string {
	return "OSS bucket without access logging"
}
func (ossNoLogging) Description() string {
	return "alicloud_oss_bucket without a logging block produces no access " +
		"logs, leaving data access unaudited. Configure a logging block " +
		"pointing at a dedicated log bucket."
}
func (ossNoLogging) Severity() ir.Severity { return ir.SeverityMedium }

func (ossNoLogging) AppliesTo(resType string) bool {
	return resType == "alicloud_oss_bucket"
}

func (s ossNoLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "logging")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "logging",
		evidenceSpan(span, r.Span), "absent (no access logging)",
		"logging { target_bucket = \"<log-bucket>\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-005: RAM account password policy too weak
// ---------------------------------------------------------------------------

type ramWeakPasswordPolicy struct{}

func (ramWeakPasswordPolicy) ID() string { return "AEGIS-ALI-005" }
func (ramWeakPasswordPolicy) Title() string {
	return "RAM account password policy too weak"
}
func (ramWeakPasswordPolicy) Description() string {
	return "alicloud_ram_account_password_policy should enforce long " +
		"passwords (minimum 14 characters) with lowercase, uppercase, " +
		"numbers and symbols, plus hard expiry and a maximum password age. " +
		"A weak policy lets attackers brute-force RAM user passwords."
}
func (ramWeakPasswordPolicy) Severity() ir.Severity { return ir.SeverityHigh }

func (ramWeakPasswordPolicy) AppliesTo(resType string) bool {
	return resType == "alicloud_ram_account_password_policy"
}

func (s ramWeakPasswordPolicy) Check(r ir.Resource) []ir.Finding {
	var problems []string
	var firstSpan ir.Span
	mark := func(attr string, span ir.Span, why string) {
		problems = append(problems, attr+": "+why)
		if firstSpan.File == "" {
			firstSpan = span
		}
	}
	if n, span, present, known := getNum(r, "minimum_password_length"); present && known {
		if n < 14 {
			mark("minimum_password_length", span, "below 14")
		}
	} else if !present {
		mark("minimum_password_length", r.Span, "absent (default 8)")
	}
	for _, attr := range []string{
		"require_lowercase_characters",
		"require_uppercase_characters",
		"require_numbers",
		"require_symbols",
	} {
		if b, span, present, known := getBool(r, attr); present && known {
			if !b {
				mark(attr, span, "false")
			}
		} else if !present {
			mark(attr, r.Span, "absent (default false)")
		}
	}
	if b, span, present, known := getBool(r, "hard_expiry"); present && known {
		if !b {
			mark("hard_expiry", span, "false")
		}
	} else if !present {
		mark("hard_expiry", r.Span, "absent (default false)")
	}
	if n, span, present, known := getNum(r, "max_password_age"); present && known {
		if n <= 0 || n > 90 {
			mark("max_password_age", span, "not within 1-90 days")
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "alicloud_ram_account_password_policy",
		evidenceSpan(firstSpan, r.Span),
		"weak password policy ("+strings.Join(problems, "; ")+")",
		"minimum_password_length >= 14 with lowercase/uppercase/numbers/symbols, hard_expiry = true, max_password_age <= 90")}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-006: RAM login profile without MFA bind requirement
// ---------------------------------------------------------------------------

type ramLoginNoMFA struct{}

func (ramLoginNoMFA) ID() string { return "AEGIS-ALI-006" }
func (ramLoginNoMFA) Title() string {
	return "RAM login profile without MFA bind requirement"
}
func (ramLoginNoMFA) Description() string {
	return "alicloud_ram_login_profile without mfa_bind_required = true lets " +
		"RAM users sign in to the console with only a password. Require MFA " +
		"binding at first login."
}
func (ramLoginNoMFA) Severity() ir.Severity { return ir.SeverityHigh }

func (ramLoginNoMFA) AppliesTo(resType string) bool {
	return resType == "alicloud_ram_login_profile"
}

func (s ramLoginNoMFA) Check(r ir.Resource) []ir.Finding {
	b, span, present, known := getBool(r, "mfa_bind_required")
	if present && !known {
		return nil
	}
	if present && b {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(s, r, "mfa_bind_required",
		evidenceSpan(span, r.Span), actual, "mfa_bind_required = true")}
}
