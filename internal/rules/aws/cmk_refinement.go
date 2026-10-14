// Package aws — customer-managed-key (CMK) refinement rules (AEGIS-AWS-852..854).
//
// Trivy parity gap: Trivy fires AVD-AWS-0132 (S3), AVD-AWS-0022
// (DocumentDB) and AVD-AWS-0128 (Neptune) when a resource is encrypted
// with an AWS-managed key instead of a customer-managed key, and Aegis
// had no equivalent rules. These rules close that gap with one
// deliberate design choice: they fire ONLY on resources that are
// already encrypted with an AWS-managed key. Unencrypted resources are
// the stronger rules' job (001 S3, 351 DocumentDB, 352 Neptune), so
// these never duplicate them.
//
// Severity Low throughout: the data IS encrypted at rest; a CMK adds
// key lifecycle control (rotation policy, grants, audit, disable/delete)
// rather than fixing exposed data.
package aws

import (
	"strings"

	"aegis/internal/ir"
)

// CMKRefinementRules returns CMK refinement rules in ID order.
func CMKRefinementRules() []ir.Rule {
	return []ir.Rule{
		s3NoCMK{},        // AEGIS-AWS-852
		docdbNoCMK{},     // AEGIS-AWS-853
		neptuneNoCMK{},   // AEGIS-AWS-854
		ebsVolumeNoCMK{}, // AEGIS-AWS-855
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-852: S3 bucket encrypted with AWS-managed key, no CMK
// ---------------------------------------------------------------------------

type s3NoCMK struct{}

func (s3NoCMK) ID() string { return "AEGIS-AWS-852" }
func (s3NoCMK) Title() string {
	return "S3 bucket encrypted with AWS-managed key, no customer-managed key"
}
func (s3NoCMK) Description() string {
	return "This bucket encrypts objects with an AWS-managed key (SSE-S3 " +
		"AES256, or SSE-KMS with the AWS-managed aws/s3 key) instead of a " +
		"customer-managed KMS key. A CMK gives you key rotation control, " +
		"grants, CloudTrail audit of key use, and the ability to disable " +
		"or delete the key. Set kms_master_key_id to a customer-managed key. " +
		"Unencrypted buckets are AEGIS-AWS-001's job and are not reported here."
}
func (s3NoCMK) Severity() ir.Severity { return ir.SeverityLow }

func (s3NoCMK) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket" ||
		resType == "aws_s3_bucket_server_side_encryption_configuration"
}

func (s3NoCMK) Check(r ir.Resource) []ir.Finding { return nil } // CheckAll owns this rule

var _ ir.CrossResourceRule = s3NoCMK{}

// sseCfg is the resolved server-side-encryption configuration for one bucket.
type sseCfg struct {
	found     bool // an SSE configuration exists (inline or standalone)
	encrypted bool // an SSE algorithm is set
	unknown   bool // algorithm/key could not be resolved
	algorithm string
	kmsKey    string
}

// sseFromApplyBlocks extracts algorithm + key from
// apply_server_side_encryption_by_default blocks.
func sseFromApplyBlocks(apply []map[string]ir.Value) sseCfg {
	cfg := sseCfg{}
	for _, def := range apply {
		algo, _, present, known := blockString(def, "sse_algorithm")
		if present && !known {
			return sseCfg{found: true, unknown: true}
		}
		if present && strings.TrimSpace(algo) != "" {
			cfg.found = true
			cfg.encrypted = true
			cfg.algorithm = strings.TrimSpace(algo)
			if key, _, kPresent, kKnown := blockString(def, "kms_master_key_id"); kPresent {
				if !kKnown {
					return sseCfg{found: true, unknown: true}
				}
				cfg.kmsKey = strings.TrimSpace(key)
			}
			return cfg
		}
	}
	return cfg
}

// sseFromInline reads the inline server_side_encryption_configuration
// block on a bucket (TF inline or CFN BucketEncryption in TF shape).
func sseFromInline(b ir.Resource) sseCfg {
	blks, _, present, known := getBlocks(b, "server_side_encryption_configuration")
	if !present || len(blks) == 0 {
		return sseCfg{}
	}
	if !known {
		return sseCfg{found: true, unknown: true}
	}
	for _, blk := range blks {
		for _, rule := range blockList(blk, "rule") {
			if cfg := sseFromApplyBlocks(blockList(rule, "apply_server_side_encryption_by_default")); cfg.found {
				return cfg
			}
		}
	}
	return sseCfg{found: true} // block exists but no usable algorithm
}

// sseFromStandalone reads a standalone
// aws_s3_bucket_server_side_encryption_configuration resource (its
// top-level block is named "rule").
func sseFromStandalone(c ir.Resource) sseCfg {
	rules, _, present, known := getBlocks(c, "rule")
	if !present || len(rules) == 0 {
		return sseCfg{}
	}
	if !known {
		return sseCfg{found: true, unknown: true}
	}
	for _, rule := range rules {
		if cfg := sseFromApplyBlocks(blockList(rule, "apply_server_side_encryption_by_default")); cfg.found {
			return cfg
		}
	}
	return sseCfg{found: true}
}

// isAWSManagedS3Key reports whether a KMS key identifier is the
// AWS-managed S3 key (aws/s3) rather than a customer-managed key.
// Matches the alias, the ARN suffix forms, and the bare key name.
func isAWSManagedS3Key(key string) bool {
	k := strings.TrimSpace(key)
	return k == "aws/s3" || k == "alias/aws/s3" ||
		strings.HasSuffix(k, ":key/aws/s3") ||
		strings.HasSuffix(k, ":alias/aws/s3") ||
		strings.HasSuffix(k, "/aws/s3")
}

// CheckAll fires on buckets whose resolved SSE uses an AWS-managed key.
// Same exemptions as 001: log-delivery targets and intentionally-public
// buckets are not judged (infrastructure / published content).
func (s3NoCMK) CheckAll(resources []ir.Resource) []ir.Finding {
	standalone := map[string]sseCfg{}
	for _, r := range resources {
		if r.Type != "aws_s3_bucket_server_side_encryption_configuration" {
			continue
		}
		if addr, ok := linkedBucketAddr(r, resources); ok {
			standalone[addr] = sseFromStandalone(r)
		}
	}
	logTargets := logDeliveryBuckets(resources)
	var out []ir.Finding
	for _, b := range resources {
		if b.Type != "aws_s3_bucket" {
			continue
		}
		cfg := sseFromInline(b)
		if !cfg.found {
			if s, ok := standalone[scopeKey(b)]; ok {
				cfg = s
			}
		}
		if !cfg.found || !cfg.encrypted || cfg.unknown {
			continue // unencrypted (001's job) or unresolved
		}
		awsManaged := strings.EqualFold(cfg.algorithm, "AES256") ||
			(strings.EqualFold(cfg.algorithm, "aws:kms") &&
				(cfg.kmsKey == "" || isAWSManagedS3Key(cfg.kmsKey)))
		if !awsManaged {
			continue
		}
		if logTargets[scopeKey(b)] || bucketIntentionallyPublic(resources, b) {
			continue
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-852",
			Title:       (s3NoCMK{}).Title(),
			Description: (s3NoCMK{}).Description(),
			Severity:    ir.SeverityLow,
			Resource:    b.Address(),
			Evidence: ir.Evidence{
				Attribute: "server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm",
				Span:      evidenceSpan(ir.Span{}, b.Span),
				Actual:    "AWS-managed key (" + cfg.algorithm + ")",
				Expected:  "kms_master_key_id set to a customer-managed KMS key",
			},
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-853: DocumentDB cluster encrypted with AWS-managed key, no CMK
// ---------------------------------------------------------------------------

type docdbNoCMK struct{}

func (docdbNoCMK) ID() string { return "AEGIS-AWS-853" }
func (docdbNoCMK) Title() string {
	return "DocumentDB cluster encrypted with AWS-managed key, no customer-managed key"
}
func (docdbNoCMK) Description() string {
	return "This DocumentDB cluster is encrypted (storage_encrypted = true) " +
		"with the AWS-managed key instead of a customer-managed KMS key. " +
		"A CMK gives you key rotation control, grants, CloudTrail audit " +
		"of key use, and the ability to disable or delete the key. Set " +
		"kms_key_id to a customer-managed key. Unencrypted clusters are " +
		"AEGIS-AWS-351's job and are not reported here."
}
func (docdbNoCMK) Severity() ir.Severity { return ir.SeverityLow }
func (docdbNoCMK) AppliesTo(resType string) bool {
	return resType == "aws_docdb_cluster"
}

func (docdbNoCMK) Check(r ir.Resource) []ir.Finding {
	en, _, present, known := getBool(r, "storage_encrypted")
	if !present || !known || !en {
		return nil // unencrypted (351's job) or unresolved
	}
	key, _, kPresent, kKnown := getString(r, "kms_key_id")
	if kPresent && !kKnown {
		return nil // unresolved: cannot decide
	}
	if kPresent && strings.TrimSpace(key) != "" {
		return nil // CMK present
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-853",
		Title:       (docdbNoCMK{}).Title(),
		Description: (docdbNoCMK{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "kms_key_id",
			Span:      evidenceSpan(ir.Span{}, r.Span),
			Actual:    "absent (AWS-managed key)",
			Expected:  "kms_key_id set to a customer-managed KMS key",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-854: Neptune cluster encrypted with AWS-managed key, no CMK
// ---------------------------------------------------------------------------

type neptuneNoCMK struct{}

func (neptuneNoCMK) ID() string { return "AEGIS-AWS-854" }
func (neptuneNoCMK) Title() string {
	return "Neptune cluster encrypted with AWS-managed key, no customer-managed key"
}
func (neptuneNoCMK) Description() string {
	return "This Neptune cluster is encrypted (storage_encrypted = true) " +
		"with the AWS-managed key instead of a customer-managed KMS key. " +
		"A CMK gives you key rotation control, grants, CloudTrail audit " +
		"of key use, and the ability to disable or delete the key. Set " +
		"kms_key_id to a customer-managed key. Unencrypted clusters are " +
		"AEGIS-AWS-352's job and are not reported here."
}
func (neptuneNoCMK) Severity() ir.Severity { return ir.SeverityLow }
func (neptuneNoCMK) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}

func (neptuneNoCMK) Check(r ir.Resource) []ir.Finding {
	en, _, present, known := getBool(r, "storage_encrypted")
	if !present || !known || !en {
		return nil // unencrypted (352's job) or unresolved
	}
	key, _, kPresent, kKnown := getString(r, "kms_key_id")
	if kPresent && !kKnown {
		return nil // unresolved: cannot decide
	}
	if kPresent && strings.TrimSpace(key) != "" {
		return nil // CMK present
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-854",
		Title:       (neptuneNoCMK{}).Title(),
		Description: (neptuneNoCMK{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "kms_key_id",
			Span:      evidenceSpan(ir.Span{}, r.Span),
			Actual:    "absent (AWS-managed key)",
			Expected:  "kms_key_id set to a customer-managed KMS key",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-855: EBS volume encrypted with AWS-managed key, no CMK
// ---------------------------------------------------------------------------
//
// Note: AEGIS-AWS-786 covers the account-level aws_ebs_default_kms_key
// resource; this rule covers individual volumes. A volume with
// encrypted = true and no kms_key_id uses the account default EBS key
// (aws/ebs, AWS-managed) unless the account default itself is a CMK —
// the account-default case is 786's domain, and this rule notes the
// edge in its description rather than staying silent on the common case.

type ebsVolumeNoCMK struct{}

func (ebsVolumeNoCMK) ID() string { return "AEGIS-AWS-855" }
func (ebsVolumeNoCMK) Title() string {
	return "EBS volume encrypted with AWS-managed key, no customer-managed key"
}
func (ebsVolumeNoCMK) Description() string {
	return "This EBS volume is encrypted (encrypted = true) with the " +
		"AWS-managed key instead of a customer-managed KMS key: no " +
		"kms_key_id is set, so the volume uses the account default EBS " +
		"key. A CMK gives you key rotation control, grants, CloudTrail " +
		"audit of key use, and the ability to disable or delete the key. " +
		"Set kms_key_id to a customer-managed key. (If the account " +
		"default EBS key is itself a CMK, this is a false positive — " +
		"see AEGIS-AWS-786 for the account-default control.) " +
		"Unencrypted volumes are AEGIS-AWS-009's job and are not " +
		"reported here."
}
func (ebsVolumeNoCMK) Severity() ir.Severity { return ir.SeverityLow }
func (ebsVolumeNoCMK) AppliesTo(resType string) bool {
	return resType == "aws_ebs_volume"
}

func (ebsVolumeNoCMK) Check(r ir.Resource) []ir.Finding {
	en, _, present, known := getBool(r, "encrypted")
	if !present || !known || !en {
		return nil // unencrypted (009's job) or unresolved
	}
	key, _, kPresent, kKnown := getString(r, "kms_key_id")
	if kPresent && !kKnown {
		return nil // unresolved: cannot decide
	}
	if kPresent && strings.TrimSpace(key) != "" {
		return nil // CMK present
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-855",
		Title:       (ebsVolumeNoCMK{}).Title(),
		Description: (ebsVolumeNoCMK{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "kms_key_id",
			Span:      evidenceSpan(ir.Span{}, r.Span),
			Actual:    "absent (AWS-managed account default key)",
			Expected:  "kms_key_id set to a customer-managed KMS key",
		},
	}}
}
