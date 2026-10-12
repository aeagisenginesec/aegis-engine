package aws

// Checkov-parity rules (AEGIS-AWS-443–446): high-value checks identified by
// diffing our findings against Checkov 3.3.26 on the same corpus.

import (
	"encoding/json"
	"sort"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-443: S3 bucket without SecureTransport enforcement (high)
// ---------------------------------------------------------------------------

type s3NoSecureTransport struct{}

func (s3NoSecureTransport) ID() string { return "AEGIS-AWS-443" }
func (s3NoSecureTransport) Title() string {
	return "S3 bucket policy does not enforce TLS (SecureTransport)"
}
func (s3NoSecureTransport) Description() string {
	return "Without an explicit Deny on aws:SecureTransport=false, bucket " +
		"objects can be fetched over plaintext HTTP. Add a bucket policy " +
		"statement denying s3:* when SecureTransport is false."
}
func (s3NoSecureTransport) Severity() ir.Severity { return ir.SeverityHigh }
func (s3NoSecureTransport) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket"
}
func (s3NoSecureTransport) Check(ir.Resource) []ir.Finding { return nil }

var _ ir.CrossResourceRule = s3NoSecureTransport{}

func (s3NoSecureTransport) CheckAll(resources []ir.Resource) []ir.Finding {
	var buckets []ir.Resource
	var policies []ir.Resource
	for _, r := range resources {
		switch r.Type {
		case "aws_s3_bucket":
			buckets = append(buckets, r)
		case "aws_s3_bucket_policy":
			policies = append(policies, r)
		}
	}
	// Index policies by target bucket address.
	byBucket := map[string][]ir.Resource{}
	for _, p := range policies {
		if addr, ok := policyBucketAddr(p, buckets); ok {
			byBucket[addr] = append(byBucket[addr], p)
		}
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Address() < buckets[j].Address() })
	// A bucket policy whose bucket link is unresolvable might enforce
	// SecureTransport on any bucket: no finding is decidable for buckets
	// without a proven policy.
	uncertain := companionLinkUncertain(resources, "aws_s3_bucket_policy", "bucket")
	// Buckets that serve as log-delivery targets are logging infrastructure,
	// not data buckets: skip them.
	logTargets := logDeliveryBuckets(resources)
	var out []ir.Finding
	for _, b := range buckets {
		pols := byBucket[b.Address()]
		if len(pols) == 0 {
			if uncertain || logTargets[b.Address()] {
				continue // might be covered by the unresolvable policy, or is a log target
			}
			// No policy at all: definitely no SecureTransport enforcement.
			out = append(out, s3NoSecureTransportFinding(b))
			continue
		}
		enforced := false
		undecidable := false
		for _, p := range pols {
			doc, _, _, known := getString(p, "policy")
			if !known {
				undecidable = true // refs in policy: cannot prove absence of deny
				continue
			}
			if policyEnforcesSecureTransport(doc) {
				enforced = true
				break
			}
		}
		if enforced || undecidable || logTargets[b.Address()] {
			continue
		}
		out = append(out, s3NoSecureTransportFinding(b))
	}
	return out
}

func s3NoSecureTransportFinding(b ir.Resource) ir.Finding {
	return ir.Finding{
		RuleID:      "AEGIS-AWS-443",
		Title:       (s3NoSecureTransport{}).Title(),
		Description: (s3NoSecureTransport{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    b.Address(),
		Evidence: ir.Evidence{
			Attribute: "policy",
			Span:      b.Span,
			Actual:    "no Deny on aws:SecureTransport=false",
			Expected:  "bucket policy denying s3:* when SecureTransport is false",
		},
	}
}

// policyEnforcesSecureTransport reports whether a policy JSON string contains
// a Deny statement conditioned on aws:SecureTransport=false.
func policyEnforcesSecureTransport(doc string) bool {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
	}
	stmts, ok := parsed["Statement"].([]any)
	if !ok {
		return false
	}
	for _, s := range stmts {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		eff, _ := m["Effect"].(string)
		if !strings.EqualFold(eff, "Deny") {
			continue
		}
		cond, ok := m["Condition"].(map[string]any)
		if !ok {
			continue
		}
		if conditionDeniesInsecureTransport(cond) {
			return true
		}
	}
	return false
}

func conditionDeniesInsecureTransport(cond map[string]any) bool {
	var walk func(v any) bool
	walk = func(v any) bool {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				if strings.EqualFold(k, "aws:SecureTransport") {
					switch s := val.(type) {
					case string:
						if strings.EqualFold(s, "false") {
							return true
						}
					case bool:
						if !s {
							return true
						}
					}
				}
				if walk(val) {
					return true
				}
			}
		case []any:
			for _, e := range t {
				if walk(e) {
					return true
				}
			}
		}
		return false
	}
	return walk(cond)
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-444: EC2 instance with public IP (high)
// ---------------------------------------------------------------------------

type ec2PublicIP struct{}

func (ec2PublicIP) ID() string    { return "AEGIS-AWS-444" }
func (ec2PublicIP) Title() string { return "EC2 instance with public IP address" }
func (ec2PublicIP) Description() string {
	return "An instance with associate_public_ip_address=true is directly " +
		"reachable from the internet. Use a load balancer or bastion instead."
}
func (ec2PublicIP) Severity() ir.Severity { return ir.SeverityHigh }
func (ec2PublicIP) AppliesTo(resType string) bool {
	return resType == "aws_instance"
}

func (ec2PublicIP) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "associate_public_ip_address")
	if !present || !known || !pub {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-444",
		Title:       (ec2PublicIP{}).Title(),
		Description: (ec2PublicIP{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "associate_public_ip_address",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (or omitted)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-445: S3 bucket without access logging (medium)
// ---------------------------------------------------------------------------

type s3NoAccessLogging struct{}

func (s3NoAccessLogging) ID() string { return "AEGIS-AWS-445" }
func (s3NoAccessLogging) Title() string {
	return "S3 bucket without server access logging"
}
func (s3NoAccessLogging) Description() string {
	return "Server access logging records requests against the bucket, " +
		"which is essential for audit and incident response."
}
func (s3NoAccessLogging) Severity() ir.Severity { return ir.SeverityMedium }
func (s3NoAccessLogging) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket" || resType == "aws_s3_bucket_logging"
}

// CheckAll suppresses the inline finding when a standalone
// aws_s3_bucket_logging resource is linked to the bucket.
// Buckets that serve as log targets (target_bucket) are also skipped:
// a dedicated log-delivery bucket does not need its own access logging.
func (s3NoAccessLogging) CheckAll(resources []ir.Resource) []ir.Finding {
	logged := map[string]bool{}
	for _, r := range resources {
		if r.Type != "aws_s3_bucket_logging" {
			continue
		}
		if addr, ok := linkedBucketAddr(r, resources); ok {
			logged[addr] = true
		}
	}
	logTargets := logDeliveryBuckets(resources)
	// A logging configuration whose bucket link is unresolvable might log
	// any bucket.
	uncertain := companionLinkUncertain(resources, "aws_s3_bucket_logging", "bucket")
	var out []ir.Finding
	for _, r := range resources {
		if r.Type != "aws_s3_bucket" {
			continue
		}
		for _, f := range (s3NoAccessLogging{}).Check(r) {
			if !logged[r.Address()] && !logTargets[r.Address()] && !uncertain {
				out = append(out, f)
			}
		}
	}
	return out
}

var _ ir.CrossResourceRule = s3NoAccessLogging{}

func (s3NoAccessLogging) Check(r ir.Resource) []ir.Finding {
	blocks, _, present, known := getBlocks(r, "logging")
	if present && !known {
		return nil // unresolved logging block: cannot decide
	}
	if !present || len(blocks) == 0 {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-445",
			Title:       (s3NoAccessLogging{}).Title(),
			Description: (s3NoAccessLogging{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "logging",
				Span:      r.Span,
				Actual:    "absent",
				Expected:  "logging { target_bucket = ... }",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-446: RDS instance without Multi-AZ (medium)
// ---------------------------------------------------------------------------

type rdsNoMultiAZ struct{}

func (rdsNoMultiAZ) ID() string    { return "AEGIS-AWS-446" }
func (rdsNoMultiAZ) Title() string { return "RDS instance without Multi-AZ" }
func (rdsNoMultiAZ) Description() string {
	return "Single-AZ RDS instances have no standby for failover. " +
		"Enable multi_az for production databases."
}
func (rdsNoMultiAZ) Severity() ir.Severity { return ir.SeverityMedium }
func (rdsNoMultiAZ) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}

func (rdsNoMultiAZ) Check(r ir.Resource) []ir.Finding {
	mz, span, present, known := getBool(r, "multi_az")
	if present && known && mz {
		return nil
	}
	if present && !known {
		return nil // unresolved: cannot decide
	}
	actual := "absent (provider default: false)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-446",
		Title:       (rdsNoMultiAZ{}).Title(),
		Description: (rdsNoMultiAZ{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "multi_az",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}

// CheckovParityRules returns the Checkov-parity rules in ID order.
func CheckovParityRules() []ir.Rule {
	return []ir.Rule{
		s3NoSecureTransport{},
		ec2PublicIP{},
		s3NoAccessLogging{},
		rdsNoMultiAZ{},
	}
}
