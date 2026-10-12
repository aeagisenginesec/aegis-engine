package aws

import (
	"sort"
	"strings"

	"aegis/internal/ir"
)

// getNumber classifies a numeric attribute into a tri-state. The adapter
// stores HCL numbers as float64; anything else (or unresolved) is unknown.
func getNumber(r ir.Resource, name string) (val float64, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return 0, ir.Span{}, false, false
	}
	if !v.Known {
		return 0, v.Span, true, false
	}
	f, ok := v.Raw.(float64)
	if !ok {
		return 0, v.Span, true, false
	}
	return f, v.Span, true, true
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-201: Load balancer internet-facing
// ---------------------------------------------------------------------------

type lbInternetFacing struct{}

func (lbInternetFacing) ID() string { return "AEGIS-AWS-201" }
func (lbInternetFacing) Title() string {
	return "Load balancer internet-facing"
}
func (lbInternetFacing) Description() string {
	return "A load balancer with internal absent or false is internet-facing " +
		"(false is the provider default). Internet-facing LBs widen the " +
		"attack surface and should be a deliberate choice."
}
func (lbInternetFacing) Severity() ir.Severity { return ir.SeverityHigh }

func (lbInternetFacing) AppliesTo(resType string) bool {
	return resType == "aws_lb" || resType == "aws_alb"
}

func (lbInternetFacing) Check(r ir.Resource) []ir.Finding {
	internal, span, present, known := getBool(r, "internal")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && internal {
		return nil // explicitly internal
	}
	actual := "false (default)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-201",
		Title:       (lbInternetFacing{}).Title(),
		Description: (lbInternetFacing{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "internal",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "internal = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-202: Load balancer listener uses plain HTTP
// ---------------------------------------------------------------------------

type lbListenerPlainHTTP struct{}

func (lbListenerPlainHTTP) ID() string { return "AEGIS-AWS-202" }
func (lbListenerPlainHTTP) Title() string {
	return "Load balancer listener uses plain HTTP"
}
func (lbListenerPlainHTTP) Description() string {
	return "A listener terminating plain HTTP sends credentials and session " +
		"tokens in cleartext. Listeners should use HTTPS (or TLS) with a " +
		"certificate."
}
func (lbListenerPlainHTTP) Severity() ir.Severity { return ir.SeverityCritical }

func (lbListenerPlainHTTP) AppliesTo(resType string) bool {
	return resType == "aws_lb_listener" || resType == "aws_alb_listener"
}

func (lbListenerPlainHTTP) Check(r ir.Resource) []ir.Finding {
	proto, span, present, known := getString(r, "protocol")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(proto), "HTTP") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-202",
		Title:       (lbListenerPlainHTTP{}).Title(),
		Description: (lbListenerPlainHTTP{}).Description(),
		Severity:    ir.SeverityCritical,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "protocol",
			Span:      evidenceSpan(span, r.Span),
			Actual:    proto,
			Expected:  "HTTPS (or TLS) with a certificate",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-203: Load balancer not dropping invalid headers
// ---------------------------------------------------------------------------

type lbNoHeaderDrop struct{}

func (lbNoHeaderDrop) ID() string { return "AEGIS-AWS-203" }
func (lbNoHeaderDrop) Title() string {
	return "Load balancer not dropping invalid headers"
}
func (lbNoHeaderDrop) Description() string {
	return "Without drop_invalid_header_fields, malformed HTTP headers reach " +
		"targets and enable request-smuggling style attacks. The provider " +
		"default is false."
}
func (lbNoHeaderDrop) Severity() ir.Severity { return ir.SeverityHigh }

func (lbNoHeaderDrop) AppliesTo(resType string) bool {
	return resType == "aws_lb" || resType == "aws_alb"
}

func (lbNoHeaderDrop) Check(r ir.Resource) []ir.Finding {
	drop, span, present, known := getBool(r, "drop_invalid_header_fields")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && drop {
		return nil
	}
	actual := "false (default)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-203",
		Title:       (lbNoHeaderDrop{}).Title(),
		Description: (lbNoHeaderDrop{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "drop_invalid_header_fields",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "drop_invalid_header_fields = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-204: EC2 instance without IMDSv2 enforcement
// ---------------------------------------------------------------------------

type ec2NoIMDSv2 struct{}

func (ec2NoIMDSv2) ID() string { return "AEGIS-AWS-204" }
func (ec2NoIMDSv2) Title() string {
	return "EC2 instance without IMDSv2 enforcement"
}
func (ec2NoIMDSv2) Description() string {
	return "Without metadata_options.http_tokens = \"required\", the instance " +
		"metadata service accepts IMDSv1 requests, which SSRF vulnerabilities " +
		"can abuse to steal credentials."
}
func (ec2NoIMDSv2) Severity() ir.Severity { return ir.SeverityHigh }

func (ec2NoIMDSv2) AppliesTo(resType string) bool {
	return resType == "aws_instance" || resType == "aws_launch_template"
}

func (ec2NoIMDSv2) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "metadata_options")
	if present && !known {
		return nil // unresolved block: cannot decide
	}
	mk := func(actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-204",
			Title:       (ec2NoIMDSv2{}).Title(),
			Description: (ec2NoIMDSv2{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "metadata_options.http_tokens",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "metadata_options { http_tokens = \"required\" }",
			},
		}}
	}
	if !present || len(blks) == 0 {
		return mk("absent (provider default allows IMDSv1)")
	}
	for _, b := range blks {
		tokens, _, tpresent, tknown := blockString(b, "http_tokens")
		if tpresent && !tknown {
			return nil // unresolved: cannot decide
		}
		if !tpresent {
			return mk("absent (provider default allows IMDSv1)")
		}
		if strings.EqualFold(strings.TrimSpace(tokens), "required") {
			return nil // IMDSv2 enforced
		}
		return mk(tokens)
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-205: Subnet auto-assigns public IPs
// ---------------------------------------------------------------------------

type subnetPublicIP struct{}

func (subnetPublicIP) ID() string { return "AEGIS-AWS-205" }
func (subnetPublicIP) Title() string {
	return "Subnet auto-assigns public IPs"
}
func (subnetPublicIP) Description() string {
	return "map_public_ip_on_launch = true gives every instance in the subnet " +
		"a public address by default, bypassing the intended private-subnet " +
		"design."
}
func (subnetPublicIP) Severity() ir.Severity { return ir.SeverityHigh }

func (subnetPublicIP) AppliesTo(resType string) bool { return resType == "aws_subnet" }

func (subnetPublicIP) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "map_public_ip_on_launch")
	if !present || !known || !pub {
		return nil // absent/false/unresolved: default is private
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-205",
		Title:       (subnetPublicIP{}).Title(),
		Description: (subnetPublicIP{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "map_public_ip_on_launch",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "map_public_ip_on_launch = false (or omitted)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-206: S3 bucket without public access block
// ---------------------------------------------------------------------------

type s3NoPublicAccessBlock struct{}

func (s3NoPublicAccessBlock) ID() string { return "AEGIS-AWS-206" }
func (s3NoPublicAccessBlock) Title() string {
	return "S3 bucket without public access block"
}
func (s3NoPublicAccessBlock) Description() string {
	return "Without an aws_s3_bucket_public_access_block enabling all four " +
		"protections (block_public_acls, block_public_policy, " +
		"ignore_public_acls, restrict_public_buckets), a single permissive " +
		"ACL or policy can expose the bucket. Fail-safe: only a proven " +
		"all-four-true block silences this rule."
}
func (s3NoPublicAccessBlock) Severity() ir.Severity { return ir.SeverityHigh }

func (s3NoPublicAccessBlock) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (s3NoPublicAccessBlock) Check(ir.Resource) []ir.Finding { return nil }

func (s3NoPublicAccessBlock) CheckAll(resources []ir.Resource) []ir.Finding {
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	// Index public-access-block resources by the bucket address they target.
	blocks := map[string][]ir.Resource{}
	for _, r := range sorted {
		if r.Type != "aws_s3_bucket_public_access_block" {
			continue
		}
		if addr, ok := pabBucketAddr(r, sorted); ok {
			blocks[addr] = append(blocks[addr], r)
		}
	}
	// A public-access-block whose bucket link is unresolvable might protect
	// any bucket: without proven coverage no finding is decidable.
	uncertain := companionLinkUncertain(sorted, "aws_s3_bucket_public_access_block", "bucket")
	var out []ir.Finding
	for _, b := range sorted {
		if b.Type != "aws_s3_bucket" {
			continue
		}
		protected := false
		for _, pab := range blocks[b.Address()] {
			if pabBlocksAll(pab) {
				protected = true
				break
			}
		}
		if protected || uncertain {
			continue
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-206",
			Title:       (s3NoPublicAccessBlock{}).Title(),
			Description: (s3NoPublicAccessBlock{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    b.Address(),
			Evidence: ir.Evidence{
				Attribute: "aws_s3_bucket_public_access_block",
				Span:      b.Span,
				Actual:    "absent or not all four protections enabled",
				Expected:  "public access block with all four settings = true",
			},
		})
	}
	return out
}

var _ ir.CrossResourceRule = s3NoPublicAccessBlock{}

// pabBucketAddr resolves which bucket a public-access-block targets via its
// `bucket` attribute: a reference ("aws_s3_bucket.assets.id") or a known
// name matched against the bucket set. Unresolvable -> false.
func pabBucketAddr(r ir.Resource, buckets []ir.Resource) (string, bool) {
	v, ok := r.Attributes["bucket"]
	if !ok {
		return "", false
	}
	if v.IsRef() {
		return refAddrOf(v.Ref)
	}
	name, ok := v.AsString()
	if !ok {
		return "", false // unknown or misshapen: cannot attribute
	}
	name = strings.TrimSpace(name)
	for _, b := range buckets {
		if b.Type != "aws_s3_bucket" {
			continue
		}
		if b.Name == name {
			return b.Address(), true
		}
		if bn, _, _, known := getString(b, "bucket"); known && strings.TrimSpace(bn) == name {
			return b.Address(), true
		}
	}
	return "", false
}

// pabBlocksAll reports whether the access-block resource enables all four
// protections with KNOWN true values. Anything else (absent, false,
// unknown) means the protection is not proven -> false.
func pabBlocksAll(r ir.Resource) bool {
	for _, name := range []string{
		"block_public_acls",
		"block_public_policy",
		"ignore_public_acls",
		"restrict_public_buckets",
	} {
		v, ok := r.Attributes[name]
		if !ok {
			return false
		}
		b, kok := v.AsBool()
		if !kok || !b {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-207: RDS instance without backup retention
// ---------------------------------------------------------------------------

type rdsNoBackup struct{}

func (rdsNoBackup) ID() string { return "AEGIS-AWS-207" }
func (rdsNoBackup) Title() string {
	return "RDS instance without backup retention"
}
func (rdsNoBackup) Description() string {
	return "With backup_retention_period absent or 0, automated backups are " +
		"disabled and point-in-time recovery is impossible after data loss."
}
func (rdsNoBackup) Severity() ir.Severity { return ir.SeverityMedium }

func (rdsNoBackup) AppliesTo(resType string) bool { return resType == "aws_db_instance" }

func (rdsNoBackup) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNumber(r, "backup_retention_period")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && days > 0 {
		return nil
	}
	actual := "absent (provider default: no backups)"
	if present {
		actual = "0"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-207",
		Title:       (rdsNoBackup{}).Title(),
		Description: (rdsNoBackup{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "backup_retention_period",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "backup_retention_period > 0 (e.g. 7)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-208: ElastiCache replication group without snapshots
// ---------------------------------------------------------------------------

type elasticacheNoSnapshots struct{}

func (elasticacheNoSnapshots) ID() string { return "AEGIS-AWS-208" }
func (elasticacheNoSnapshots) Title() string {
	return "ElastiCache replication group without snapshots"
}
func (elasticacheNoSnapshots) Description() string {
	return "With snapshot_retention_limit absent or 0, automated snapshots " +
		"are disabled and cache data cannot be restored after loss."
}
func (elasticacheNoSnapshots) Severity() ir.Severity { return ir.SeverityMedium }

func (elasticacheNoSnapshots) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}

func (elasticacheNoSnapshots) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNumber(r, "snapshot_retention_limit")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && days > 0 {
		return nil
	}
	actual := "absent (provider default: no snapshots)"
	if present {
		actual = "0"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-208",
		Title:       (elasticacheNoSnapshots{}).Title(),
		Description: (elasticacheNoSnapshots{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "snapshot_retention_limit",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "snapshot_retention_limit > 0 (e.g. 7)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-209: VPC without flow logs
// ---------------------------------------------------------------------------

type vpcNoFlowLogs struct{}

func (vpcNoFlowLogs) ID() string { return "AEGIS-AWS-209" }
func (vpcNoFlowLogs) Title() string {
	return "VPC without flow logs"
}
func (vpcNoFlowLogs) Description() string {
	return "Without an aws_flow_log attached to the VPC, network traffic " +
		"metadata is not captured and incident investigation is blind. " +
		"Fail-safe: a VPC with no linked flow log is flagged."
}
func (vpcNoFlowLogs) Severity() ir.Severity { return ir.SeverityMedium }

func (vpcNoFlowLogs) AppliesTo(resType string) bool { return resType == "aws_vpc" }

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (vpcNoFlowLogs) Check(ir.Resource) []ir.Finding { return nil }

func (vpcNoFlowLogs) CheckAll(resources []ir.Resource) []ir.Finding {
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	// Index flow logs by the VPC address they target via vpc_id.
	logged := map[string]bool{}
	for _, r := range sorted {
		if r.Type != "aws_flow_log" {
			continue
		}
		if addr, ok := flowLogVPCAddr(r, sorted); ok {
			logged[addr] = true
		}
	}
	// A flow log whose vpc_id is unresolvable might log any VPC.
	uncertain := companionLinkUncertain(sorted, "aws_flow_log", "vpc_id")
	var out []ir.Finding
	for _, v := range sorted {
		if v.Type != "aws_vpc" {
			continue
		}
		if logged[v.Address()] || uncertain {
			continue
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-209",
			Title:       (vpcNoFlowLogs{}).Title(),
			Description: (vpcNoFlowLogs{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    v.Address(),
			Evidence: ir.Evidence{
				Attribute: "aws_flow_log",
				Span:      v.Span,
				Actual:    "no flow log attached to this VPC",
				Expected:  "aws_flow_log with vpc_id referencing this VPC",
			},
		})
	}
	return out
}

var _ ir.CrossResourceRule = vpcNoFlowLogs{}

// flowLogVPCAddr resolves which VPC a flow log targets via its `vpc_id`
// attribute: a reference ("aws_vpc.main.id") or a known string matched
// against VPC names. Unresolvable -> false.
func flowLogVPCAddr(r ir.Resource, vpcs []ir.Resource) (string, bool) {
	v, ok := r.Attributes["vpc_id"]
	if !ok {
		return "", false
	}
	if v.IsRef() {
		return refAddrOf(v.Ref)
	}
	id, ok := v.AsString()
	if !ok {
		return "", false // unknown or misshapen: cannot attribute
	}
	id = strings.TrimSpace(id)
	for _, vp := range vpcs {
		if vp.Type != "aws_vpc" {
			continue
		}
		if vp.Name == id {
			return vp.Address(), true
		}
	}
	return "", false
}
