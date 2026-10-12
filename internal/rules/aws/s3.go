package aws

import (
	"encoding/json"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-001: S3 bucket without server-side encryption
// ---------------------------------------------------------------------------

type s3Encryption struct{}

func (s3Encryption) ID() string    { return "AEGIS-AWS-001" }
func (s3Encryption) Title() string { return "S3 bucket without server-side encryption" }
func (s3Encryption) Description() string {
	return "S3 buckets should encrypt objects at rest. A bucket with no " +
		"server_side_encryption_configuration block relies on the account default, " +
		"which may not exist. Standalone aws_s3_bucket_server_side_encryption_configuration " +
		"resources are acknowledged but require graph correlation to attribute."
}
func (s3Encryption) Severity() ir.Severity { return ir.SeverityHigh }

func (s3Encryption) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket" ||
		resType == "aws_s3_bucket_server_side_encryption_configuration"
}

// CheckAll suppresses the inline finding when a standalone
// aws_s3_bucket_server_side_encryption_configuration is linked to the bucket.
// Buckets that serve as log-delivery targets are skipped: they are logging
// infrastructure, not data buckets.
func (s3Encryption) CheckAll(resources []ir.Resource) []ir.Finding {
	encrypted := map[string]bool{}
	for _, r := range resources {
		if r.Type != "aws_s3_bucket_server_side_encryption_configuration" {
			continue
		}
		if addr, ok := linkedBucketAddr(r, resources); ok {
			encrypted[addr] = true
		}
	}
	logTargets := logDeliveryBuckets(resources)
	var out []ir.Finding
	for _, r := range resources {
		if r.Type != "aws_s3_bucket" {
			continue
		}
		for _, f := range (s3Encryption{}).Check(r) {
			if !encrypted[r.Address()] && !logTargets[r.Address()] {
				out = append(out, f)
			}
		}
	}
	return out
}

var _ ir.CrossResourceRule = s3Encryption{}

func (s3Encryption) Check(r ir.Resource) []ir.Finding {
	if r.Type == "aws_s3_bucket_server_side_encryption_configuration" {
		return nil // standalone resource: encryption is configured by definition
	}
	blks, span, present, known := getBlocks(r, "server_side_encryption_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-001",
			Title:       (s3Encryption{}).Title(),
			Description: (s3Encryption{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "server_side_encryption_configuration",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent",
				Expected:  "server_side_encryption_configuration block with sse_algorithm set",
			},
		}}
	}
	// Block present: confirm at least one rule applies an SSE algorithm.
	for _, b := range blks {
		for _, rule := range blockList(b, "rule") {
			for _, def := range blockList(rule, "apply_server_side_encryption_by_default") {
				algo, asp, present, known := blockString(def, "sse_algorithm")
				if present && !known {
					return nil // algorithm unresolved: cannot decide
				}
				if present && strings.TrimSpace(algo) != "" {
					return nil // encrypted
				}
				_ = asp
			}
		}
	}
	// Block exists but no usable algorithm found.
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-001",
		Title:       (s3Encryption{}).Title(),
		Description: (s3Encryption{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "missing or empty",
			Expected:  "sse_algorithm set (e.g. AES256 or aws:kms)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-002: S3 bucket with public ACL
// ---------------------------------------------------------------------------

type s3PublicACL struct{}

func (s3PublicACL) ID() string    { return "AEGIS-AWS-002" }
func (s3PublicACL) Title() string { return "S3 bucket with public ACL" }
func (s3PublicACL) Description() string {
	return "Bucket ACLs granting public-read, public-read-write, or " +
		"authenticated-read expose objects beyond the account."
}
func (s3PublicACL) Severity() ir.Severity { return ir.SeverityHigh }

func (s3PublicACL) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket" || resType == "aws_s3_bucket_acl"
}

var publicACLs = map[string]bool{
	"public-read":        true,
	"public-read-write":  true,
	"authenticated-read": true,
}

func (s3PublicACL) Check(r ir.Resource) []ir.Finding {
	acl, span, present, known := getString(r, "acl")
	if !present {
		return nil // provider default is "private"
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if !publicACLs[strings.ToLower(strings.TrimSpace(acl))] {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-002",
		Title:       (s3PublicACL{}).Title(),
		Description: (s3PublicACL{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "acl",
			Span:      evidenceSpan(span, r.Span),
			Actual:    acl,
			Expected:  "private (or omitted)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-003: S3 bucket policy allows public principal
// ---------------------------------------------------------------------------

type s3PublicPolicy struct{}

func (s3PublicPolicy) ID() string    { return "AEGIS-AWS-003" }
func (s3PublicPolicy) Title() string { return "S3 bucket policy allows public principal" }
func (s3PublicPolicy) Description() string {
	return "An Allow statement with Principal \"*\" grants anonymous access " +
		"to the bucket, bypassing ACL controls."
}
func (s3PublicPolicy) Severity() ir.Severity { return ir.SeverityCritical }

func (s3PublicPolicy) AppliesTo(resType string) bool { return resType == "aws_s3_bucket_policy" }

func (s3PublicPolicy) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyAllowsPublicPrincipal(pol) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-003",
			Title:       (s3PublicPolicy{}).Title(),
			Description: (s3PublicPolicy{}).Description(),
			Severity:    ir.SeverityCritical,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "Allow statement with Principal \"*\"",
				Expected:  "no Allow statement with Principal \"*\"",
			},
		}}
	}
	return nil
}

// policyAllowsPublicPrincipal parses a policy JSON document and reports
// whether any Allow statement grants Principal "*". Malformed JSON or
// unexpected shapes yield false (cannot decide -> no finding).
func policyAllowsPublicPrincipal(doc string) bool {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
	}
	if len(parsed.Statement) == 0 {
		return false
	}
	var stmts []map[string]any
	if parsed.Statement[0] == '[' {
		if err := json.Unmarshal(parsed.Statement, &stmts); err != nil {
			return false
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(parsed.Statement, &one); err != nil {
			return false
		}
		stmts = []map[string]any{one}
	}
	for _, s := range stmts {
		eff, _ := s["Effect"].(string)
		if eff != "Allow" {
			continue
		}
		if principalIsPublic(s["Principal"]) {
			return true
		}
	}
	return false
}

// principalIsPublic reports whether a Principal value is "*" or contains "*"
// (e.g. {"AWS": "*"} or {"AWS": ["arn:...", "*"]}).
func principalIsPublic(p any) bool {
	switch v := p.(type) {
	case string:
		return strings.TrimSpace(v) == "*"
	case map[string]any:
		for _, val := range v {
			if principalIsPublic(val) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if principalIsPublic(item) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-012: S3 bucket without versioning
// ---------------------------------------------------------------------------

type s3Versioning struct{}

func (s3Versioning) ID() string    { return "AEGIS-AWS-012" }
func (s3Versioning) Title() string { return "S3 bucket without versioning" }
func (s3Versioning) Description() string {
	return "Versioning protects against accidental deletion and overwrites " +
		"and is required for reliable recovery. Provider default is disabled."
}
func (s3Versioning) Severity() ir.Severity { return ir.SeverityMedium }

func (s3Versioning) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket" || resType == "aws_s3_bucket_versioning"
}

// versioningStandaloneEnabled reports whether a standalone
// aws_s3_bucket_versioning resource enables versioning.
func versioningStandaloneEnabled(r ir.Resource) bool {
	blks, _, present, known := getBlocks(r, "versioning_configuration")
	if !present || !known || len(blks) == 0 {
		return false
	}
	for _, b := range blks {
		st, _, spresent, sknown := blockString(b, "status")
		if spresent && sknown && strings.EqualFold(strings.TrimSpace(st), "Enabled") {
			return true
		}
	}
	return false
}

// CheckAll suppresses the inline finding when a standalone
// aws_s3_bucket_versioning with status=Enabled is linked to the bucket.
// Buckets that serve as log-delivery targets are skipped: they are logging
// infrastructure, not data buckets.
func (s3Versioning) CheckAll(resources []ir.Resource) []ir.Finding {
	versioned := map[string]bool{}
	for _, r := range resources {
		if r.Type != "aws_s3_bucket_versioning" {
			continue
		}
		if addr, ok := linkedBucketAddr(r, resources); ok && versioningStandaloneEnabled(r) {
			versioned[addr] = true
		}
	}
	logTargets := logDeliveryBuckets(resources)
	var out []ir.Finding
	for _, r := range resources {
		if r.Type != "aws_s3_bucket" {
			continue
		}
		for _, f := range (s3Versioning{}).Check(r) {
			if !versioned[r.Address()] && !logTargets[r.Address()] {
				out = append(out, f)
			}
		}
	}
	return out
}

var _ ir.CrossResourceRule = s3Versioning{}

func (s3Versioning) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "versioning")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		for _, b := range blks {
			en, _, epresent, eknown := blockBool(b, "enabled")
			if epresent && !eknown {
				return nil // unresolved: cannot decide
			}
			if epresent && en {
				return nil // versioning enabled
			}
		}
	}
	// Absent or present-but-disabled: provider default is disabled.
	actual := "absent (provider default: disabled)"
	if present {
		actual = "enabled = false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-012",
		Title:       (s3Versioning{}).Title(),
		Description: (s3Versioning{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "versioning",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "versioning { enabled = true }",
		},
	}}
}
