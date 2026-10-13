// Package aws implements the Aegis AWS security rule pack.
//
// Deep compute rules (AEGIS-AWS-680–699): second-pass hardening checks for
// EC2, launch templates, auto scaling, and EBS-adjacent copy resources that
// complement the parity and first-pass rules. Unknown values never fire;
// absent attributes are evaluated against the provider's insecure default.
package aws

import (
	"fmt"
	"regexp"
	"strings"

	"aegis/internal/ir"
)

// ComputeDeepRules returns the deep-compute rules in ID order (680-699).
func ComputeDeepRules() []ir.Rule {
	return []ir.Rule{
		ec2IMDSTagsExposed{},          // AEGIS-AWS-680
		ec2IMDSHopLimitTooHigh{},     // AEGIS-AWS-681
		launchTemplateStaleDefault{}, // AEGIS-AWS-682
		ec2NoTerminationProtection{}, // AEGIS-AWS-683
		ec2PasswordDataExposed{},     // AEGIS-AWS-685
		ec2UserDataAWSCreds{},        // AEGIS-AWS-686
		ltUserDataHardcodedPassword{}, // AEGIS-AWS-687
		eniPublicIPAssociated{},      // AEGIS-AWS-688
		ec2SourceDestCheckDisabled{}, // AEGIS-AWS-689
		asgHealthCheckEC2Only{},      // AEGIS-AWS-690
		ltEBSOptimizedAbsent{},       // AEGIS-AWS-691
		ec2UnlimitedCPUCredits{},     // AEGIS-AWS-693
		amiCopyUnencrypted{},         // AEGIS-AWS-694
		ebsSnapshotCopyUnencrypted{}, // AEGIS-AWS-695
		ec2RootVolumeUnencrypted{},   // AEGIS-AWS-696
		ltEBSDeleteOnTermination{},   // AEGIS-AWS-697
		asgNoScalingRange{},          // AEGIS-AWS-698
		ec2NoNitroEnclaves{},         // AEGIS-AWS-699
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-680: EC2 instance exposes tags to the metadata service (medium)
// ---------------------------------------------------------------------------
// Replaces the originally-planned IMDSv2 instance check: AEGIS-AWS-204
// (ec2NoIMDSv2) already enforces http_tokens=required on aws_instance. This
// rule instead covers instance_metadata_tags, which 204 does not inspect.

type ec2IMDSTagsExposed struct{}

func (ec2IMDSTagsExposed) ID() string { return "AEGIS-AWS-680" }
func (ec2IMDSTagsExposed) Title() string {
	return "EC2 instance exposes resource tags to IMDS"
}
func (ec2IMDSTagsExposed) Description() string {
	return "instance_metadata_tags = \"enabled\" lets any process on the " +
		"instance read EC2 resource tags through the metadata service, " +
		"leaking names, roles, and environment labels that aid lateral movement."
}
func (ec2IMDSTagsExposed) Severity() ir.Severity { return ir.SeverityMedium }
func (ec2IMDSTagsExposed) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2IMDSTagsExposed) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "metadata_options")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	tags, span, p, k := blockString(blks[0], "instance_metadata_tags")
	if !p || !k {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(tags), "enabled") {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-680",
			Title:       (ec2IMDSTagsExposed{}).Title(),
			Description: (ec2IMDSTagsExposed{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "metadata_options.instance_metadata_tags",
				Span:      evidenceSpan(span, r.Span),
				Actual:    tags,
				Expected:  "\"disabled\" (or omitted)",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-681: EC2 IMDS hop limit above 1 (medium)
// ---------------------------------------------------------------------------

type ec2IMDSHopLimitTooHigh struct{}

func (ec2IMDSHopLimitTooHigh) ID() string { return "AEGIS-AWS-681" }
func (ec2IMDSHopLimitTooHigh) Title() string {
	return "EC2 IMDS hop limit above 1"
}
func (ec2IMDSHopLimitTooHigh) Description() string {
	return "http_put_response_hop_limit > 1 lets IMDSv2 tokens travel beyond " +
		"the instance, which weakens IMDSv2's SSRF protection; keep the hop " +
		"limit at 1 unless a proxy on the host legitimately needs it."
}
func (ec2IMDSHopLimitTooHigh) Severity() ir.Severity { return ir.SeverityMedium }
func (ec2IMDSHopLimitTooHigh) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2IMDSHopLimitTooHigh) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "metadata_options")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	hops, span, p, k := blockNumber(blks[0], "http_put_response_hop_limit")
	if !p || !k {
		return nil
	}
	if hops > 1 {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-681",
			Title:       (ec2IMDSHopLimitTooHigh{}).Title(),
			Description: (ec2IMDSHopLimitTooHigh{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "metadata_options.http_put_response_hop_limit",
				Span:      evidenceSpan(span, r.Span),
				Actual:    fmt.Sprintf("%d", int(hops)),
				Expected:  "1",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-682: Launch template never updates its default version (low)
// ---------------------------------------------------------------------------
// Replaces the originally-planned launch-template IMDSv2 check: AEGIS-AWS-204
// already enforces http_tokens=required on aws_launch_template. This covers
// the version-default hygiene gap instead.

type launchTemplateStaleDefault struct{}

func (launchTemplateStaleDefault) ID() string { return "AEGIS-AWS-682" }
func (launchTemplateStaleDefault) Title() string {
	return "Launch template does not update its default version"
}
func (launchTemplateStaleDefault) Description() string {
	return "Without update_default_version = true, new template versions never " +
		"become the default, so instances and auto scaling groups silently " +
		"keep launching from a stale version that may miss security fixes."
}
func (launchTemplateStaleDefault) Severity() ir.Severity { return ir.SeverityLow }
func (launchTemplateStaleDefault) AppliesTo(resType string) bool {
	return resType == "aws_launch_template"
}
func (launchTemplateStaleDefault) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "update_default_version")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	actual := "absent (provider default: false)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-682",
		Title:       (launchTemplateStaleDefault{}).Title(),
		Description: (launchTemplateStaleDefault{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "update_default_version",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "update_default_version = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-683: EC2 instance without termination protection (low)
// ---------------------------------------------------------------------------

type ec2NoTerminationProtection struct{}

func (ec2NoTerminationProtection) ID() string { return "AEGIS-AWS-683" }
func (ec2NoTerminationProtection) Title() string {
	return "EC2 instance without termination protection"
}
func (ec2NoTerminationProtection) Description() string {
	return "disable_api_termination is absent or false, so the instance can " +
		"be terminated by an accidental or malicious API call. Enable it " +
		"for instances that must not be deleted casually."
}
func (ec2NoTerminationProtection) Severity() ir.Severity { return ir.SeverityLow }
func (ec2NoTerminationProtection) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2NoTerminationProtection) Check(r ir.Resource) []ir.Finding {
	val, _, present, known := getBool(r, "disable_api_termination")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	if !present {
		return absentInsecureDefault(ec2NoTerminationProtection{}, r,
			"disable_api_termination",
			"absent (provider default: false)",
			"disable_api_termination = true")
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-683",
		Title:       (ec2NoTerminationProtection{}).Title(),
		Description: (ec2NoTerminationProtection{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "disable_api_termination",
			Span:      r.Span,
			Actual:    "false",
			Expected:  "disable_api_termination = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-685: EC2 instance with get_password_data enabled (medium)
// ---------------------------------------------------------------------------
// Replaces the originally-planned detailed-monitoring check: AEGIS-AWS-311
// family (ec2NoDetailedMonitoring) already covers monitoring on aws_instance.
// Password retrieval is the remaining gap in this area.

type ec2PasswordDataExposed struct{}

func (ec2PasswordDataExposed) ID() string { return "AEGIS-AWS-685" }
func (ec2PasswordDataExposed) Title() string {
	return "EC2 instance with Windows password retrieval enabled"
}
func (ec2PasswordDataExposed) Description() string {
	return "get_password_data = true exposes the Windows administrator " +
		"password through the EC2 API to anyone with ec2:GetPasswordData " +
		"permission. Keep it disabled unless the password is genuinely needed."
}
func (ec2PasswordDataExposed) Severity() ir.Severity { return ir.SeverityMedium }
func (ec2PasswordDataExposed) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2PasswordDataExposed) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "get_password_data")
	if !present || !known || !val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-685",
		Title:       (ec2PasswordDataExposed{}).Title(),
		Description: (ec2PasswordDataExposed{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "get_password_data",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (or omitted)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-686/687: hardcoded credentials in EC2 user_data (high)
// ---------------------------------------------------------------------------
// Narrower than the generic AEGIS-AWS-534 (userDataSecret): 686 targets
// AWS CLI credential pairs / access-key IDs in aws_instance user_data, and
// 687 targets hardcoded OS passwords in aws_launch_template user_data.
// Evidence never carries the secret value (see helpers contract).

var (
	awsCliCredPattern = regexp.MustCompile(
		`(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["']?[^\s"']+`)
	ec2UserDataAccessKeyPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	osPasswordPattern   = regexp.MustCompile(
		`(?i)(password|passwd)\s*[:=]\s*["']?[^\s"']{3,}`)
)

func userDataText(r ir.Resource) (string, bool) {
	for _, attr := range []string{"user_data", "user_data_base64"} {
		v, ok := r.Attributes[attr]
		if !ok || !v.Known {
			continue
		}
		s, ok := v.AsString()
		if !ok || strings.TrimSpace(s) == "" {
			continue
		}
		return s, true
	}
	return "", false
}

type ec2UserDataAWSCreds struct{}

func (ec2UserDataAWSCreds) ID() string { return "AEGIS-AWS-686" }
func (ec2UserDataAWSCreds) Title() string {
	return "EC2 user_data embeds AWS credentials"
}
func (ec2UserDataAWSCreds) Description() string {
	return "user_data contains an AWS access key ID or an " +
		"aws_access_key_id / aws_secret_access_key assignment. Long-lived " +
		"credentials baked into boot scripts are recoverable from the " +
		"console and snapshots; use an instance profile instead. The " +
		"credential value is never included in findings."
}
func (ec2UserDataAWSCreds) Severity() ir.Severity { return ir.SeverityHigh }
func (ec2UserDataAWSCreds) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2UserDataAWSCreds) Check(r ir.Resource) []ir.Finding {
	text, ok := userDataText(r)
	if !ok {
		return nil
	}
	if !awsCliCredPattern.MatchString(text) && !ec2UserDataAccessKeyPattern.MatchString(text) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-686",
		Title:       (ec2UserDataAWSCreds{}).Title(),
		Description: (ec2UserDataAWSCreds{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "user_data",
			Span:      r.Span,
			Actual:    "[REDACTED] (AWS credential assignment in user_data)",
			Expected:  "no credentials in user_data",
		},
	}}
}

type ltUserDataHardcodedPassword struct{}

func (ltUserDataHardcodedPassword) ID() string { return "AEGIS-AWS-687" }
func (ltUserDataHardcodedPassword) Title() string {
	return "Launch template user_data embeds a hardcoded password"
}
func (ltUserDataHardcodedPassword) Description() string {
	return "user_data contains a password= / passwd= assignment, baking an " +
		"OS or application password into every instance the template " +
		"launches. The password is visible to anyone who can read the " +
		"template or its launches; inject it via SSM Parameter Store or " +
		"Secrets Manager instead. The value is never included in findings."
}
func (ltUserDataHardcodedPassword) Severity() ir.Severity { return ir.SeverityHigh }
func (ltUserDataHardcodedPassword) AppliesTo(resType string) bool {
	return resType == "aws_launch_template"
}
func (ltUserDataHardcodedPassword) Check(r ir.Resource) []ir.Finding {
	text, ok := userDataText(r)
	if !ok {
		return nil
	}
	if !osPasswordPattern.MatchString(text) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-687",
		Title:       (ltUserDataHardcodedPassword{}).Title(),
		Description: (ltUserDataHardcodedPassword{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "user_data",
			Span:      r.Span,
			Actual:    "[REDACTED] (password assignment in user_data)",
			Expected:  "no passwords in user_data",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-688: network interface with public IP association (medium)
// ---------------------------------------------------------------------------
// AEGIS-AWS-444 covers aws_instance; this closes the gap for standalone
// aws_network_interface attachments.

type eniPublicIPAssociated struct{}

func (eniPublicIPAssociated) ID() string { return "AEGIS-AWS-688" }
func (eniPublicIPAssociated) Title() string {
	return "Network interface with public IP association"
}
func (eniPublicIPAssociated) Description() string {
	return "associate_public_ip_address = true on a network interface gives " +
		"the attached resource a public IP, exposing it to the internet " +
		"regardless of the instance-level setting."
}
func (eniPublicIPAssociated) Severity() ir.Severity { return ir.SeverityMedium }
func (eniPublicIPAssociated) AppliesTo(resType string) bool {
	return resType == "aws_network_interface"
}
func (eniPublicIPAssociated) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "associate_public_ip_address")
	if !present || !known || !val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-688",
		Title:       (eniPublicIPAssociated{}).Title(),
		Description: (eniPublicIPAssociated{}).Description(),
		Severity:    ir.SeverityMedium,
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
// AEGIS-AWS-689: EC2 instance with source/destination check disabled (low)
// ---------------------------------------------------------------------------

type ec2SourceDestCheckDisabled struct{}

func (ec2SourceDestCheckDisabled) ID() string { return "AEGIS-AWS-689" }
func (ec2SourceDestCheckDisabled) Title() string {
	return "EC2 instance with source/destination check disabled"
}
func (ec2SourceDestCheckDisabled) Description() string {
	return "source_dest_check = false is only legitimate for NAT instances, " +
		"routers, or firewalls. On a normal instance it disables the " +
		"anti-spoofing guard, letting the instance forward or impersonate " +
		"traffic. Confirm the host is actually a network appliance."
}
func (ec2SourceDestCheckDisabled) Severity() ir.Severity { return ir.SeverityLow }
func (ec2SourceDestCheckDisabled) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2SourceDestCheckDisabled) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "source_dest_check")
	if !present || !known || val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-689",
		Title:       (ec2SourceDestCheckDisabled{}).Title(),
		Description: (ec2SourceDestCheckDisabled{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "source_dest_check",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "true (unless the instance is a NAT/router)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-690: ASG health check limited to EC2 status (low)
// ---------------------------------------------------------------------------

type asgHealthCheckEC2Only struct{}

func (asgHealthCheckEC2Only) ID() string { return "AEGIS-AWS-690" }
func (asgHealthCheckEC2Only) Title() string {
	return "Auto scaling group with EC2-only health checks"
}
func (asgHealthCheckEC2Only) Description() string {
	return "health_check_type = \"EC2\" only replaces instances that fail " +
		"hypervisor checks. For groups behind a load balancer, \"ELB\" also " +
		"replaces instances that stop serving traffic, which EC2 checks " +
		"alone would leave in place."
}
func (asgHealthCheckEC2Only) Severity() ir.Severity { return ir.SeverityLow }
func (asgHealthCheckEC2Only) AppliesTo(resType string) bool {
	return resType == "aws_autoscaling_group"
}
func (asgHealthCheckEC2Only) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "health_check_type")
	if !present || !known {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(val), "EC2") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-690",
		Title:       (asgHealthCheckEC2Only{}).Title(),
		Description: (asgHealthCheckEC2Only{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "health_check_type",
			Span:      evidenceSpan(span, r.Span),
			Actual:    val,
			Expected:  "\"ELB\" (when behind a load balancer)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-691: launch template without ebs_optimized declared (low)
// ---------------------------------------------------------------------------

type ltEBSOptimizedAbsent struct{}

func (ltEBSOptimizedAbsent) ID() string { return "AEGIS-AWS-691" }
func (ltEBSOptimizedAbsent) Title() string {
	return "Launch template without ebs_optimized declared"
}
func (ltEBSOptimizedAbsent) Description() string {
	return "ebs_optimized is absent from the launch template, so the " +
		"provider default (false) applies to every instance launched from " +
		"it: no dedicated EBS bandwidth. Declare ebs_optimized = true for " +
		"EBS-backed workloads."
}
func (ltEBSOptimizedAbsent) Severity() ir.Severity { return ir.SeverityLow }
func (ltEBSOptimizedAbsent) AppliesTo(resType string) bool {
	return resType == "aws_launch_template"
}
func (ltEBSOptimizedAbsent) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBool(r, "ebs_optimized")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		return nil
	}
	return absentInsecureDefault(ltEBSOptimizedAbsent{}, r,
		"ebs_optimized",
		"absent (provider default: false)",
		"ebs_optimized = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-693: burstable instance with unlimited CPU credits (low)
// ---------------------------------------------------------------------------

type ec2UnlimitedCPUCredits struct{}

func (ec2UnlimitedCPUCredits) ID() string { return "AEGIS-AWS-693" }
func (ec2UnlimitedCPUCredits) Title() string {
	return "Burstable EC2 instance with unlimited CPU credits"
}
func (ec2UnlimitedCPUCredits) Description() string {
	return "credit_specification cpu_credits = \"unlimited\" on a burstable " +
		"instance silently accrues surcharges whenever the baseline is " +
		"exceeded. Confirm the workload needs it, or use \"standard\" mode."
}
func (ec2UnlimitedCPUCredits) Severity() ir.Severity { return ir.SeverityLow }
func (ec2UnlimitedCPUCredits) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2UnlimitedCPUCredits) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "credit_specification")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	credits, span, p, k := blockString(blks[0], "cpu_credits")
	if !p || !k {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(credits), "unlimited") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-693",
		Title:       (ec2UnlimitedCPUCredits{}).Title(),
		Description: (ec2UnlimitedCPUCredits{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "credit_specification.cpu_credits",
			Span:      evidenceSpan(span, r.Span),
			Actual:    credits,
			Expected:  "\"standard\" (unless unlimited is intended)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-694: AMI copy without encryption (medium)
// ---------------------------------------------------------------------------

type amiCopyUnencrypted struct{}

func (amiCopyUnencrypted) ID() string { return "AEGIS-AWS-694" }
func (amiCopyUnencrypted) Title() string {
	return "AMI copy without encryption"
}
func (amiCopyUnencrypted) Description() string {
	return "aws_ami_copy with encrypted absent or false produces an AMI " +
		"whose snapshots are unencrypted at rest, even when the source AMI " +
		"was encrypted. Set encrypted = true on copies."
}
func (amiCopyUnencrypted) Severity() ir.Severity { return ir.SeverityMedium }
func (amiCopyUnencrypted) AppliesTo(resType string) bool { return resType == "aws_ami_copy" }
func (amiCopyUnencrypted) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "encrypted")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	if !present {
		return absentInsecureDefault(amiCopyUnencrypted{}, r,
			"encrypted",
			"absent (provider default: false)",
			"encrypted = true")
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-694",
		Title:       (amiCopyUnencrypted{}).Title(),
		Description: (amiCopyUnencrypted{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "encrypted = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-695: EBS snapshot copy without encryption (medium)
// ---------------------------------------------------------------------------

type ebsSnapshotCopyUnencrypted struct{}

func (ebsSnapshotCopyUnencrypted) ID() string { return "AEGIS-AWS-695" }
func (ebsSnapshotCopyUnencrypted) Title() string {
	return "EBS snapshot copy without encryption"
}
func (ebsSnapshotCopyUnencrypted) Description() string {
	return "aws_ebs_snapshot_copy with encrypted absent or false produces " +
		"an unencrypted snapshot, even when the source snapshot was " +
		"encrypted. Set encrypted = true (with a kms_key_id) on copies."
}
func (ebsSnapshotCopyUnencrypted) Severity() ir.Severity { return ir.SeverityMedium }
func (ebsSnapshotCopyUnencrypted) AppliesTo(resType string) bool {
	return resType == "aws_ebs_snapshot_copy"
}
func (ebsSnapshotCopyUnencrypted) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "encrypted")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	if !present {
		return absentInsecureDefault(ebsSnapshotCopyUnencrypted{}, r,
			"encrypted",
			"absent (provider default: false)",
			"encrypted = true")
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-695",
		Title:       (ebsSnapshotCopyUnencrypted{}).Title(),
		Description: (ebsSnapshotCopyUnencrypted{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "encrypted = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-696: EC2 root volume without encryption (high)
// ---------------------------------------------------------------------------

type ec2RootVolumeUnencrypted struct{}

func (ec2RootVolumeUnencrypted) ID() string { return "AEGIS-AWS-696" }
func (ec2RootVolumeUnencrypted) Title() string {
	return "EC2 root volume without encryption"
}
func (ec2RootVolumeUnencrypted) Description() string {
	return "root_block_device with encrypted = false explicitly leaves the " +
		"instance's root volume unencrypted at rest, exposing the OS disk " +
		"and any data written to it. Set encrypted = true. (An omitted " +
		"root_block_device — or an omitted encrypted within it — is NOT " +
		"evidence of an unencrypted volume: encryption then follows the " +
		"AMI snapshot and the account EBS-encryption-by-default setting.)"
}
func (ec2RootVolumeUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }
func (ec2RootVolumeUnencrypted) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2RootVolumeUnencrypted) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "root_block_device")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(blks) == 0 {
		// Absent block: encryption governed by AMI snapshot + account
		// EBS-encryption-by-default, NOT a provider default of
		// unencrypted. Stay quiet (was: absentInsecureDefault FP).
		return nil
	}
	enc, span, p, k := blockBool(blks[0], "encrypted")
	if !p {
		// Present block, encrypted omitted: same AMI/account default
		// governs. Stay quiet.
		return nil
	}
	if !k {
		return nil // unresolved: cannot decide
	}
	if enc {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-696",
		Title:       (ec2RootVolumeUnencrypted{}).Title(),
		Description: (ec2RootVolumeUnencrypted{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "root_block_device.encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "encrypted = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-697: launch template EBS volume kept on termination (low)
// ---------------------------------------------------------------------------
// Replaces the originally-planned block_device_mappings encryption check:
// AEGIS-AWS-301 (launchTemplateUnencryptedEBS) already covers encrypted =
// false there. This covers delete_on_termination hygiene instead.

type ltEBSDeleteOnTermination struct{}

func (ltEBSDeleteOnTermination) ID() string { return "AEGIS-AWS-697" }
func (ltEBSDeleteOnTermination) Title() string {
	return "Launch template EBS volume kept after instance termination"
}
func (ltEBSDeleteOnTermination) Description() string {
	return "block_device_mappings ebs delete_on_termination = false leaves " +
		"orphaned volumes behind when instances die: they keep billing and " +
		"retain whatever data the instance wrote. Set delete_on_termination " +
		"= true unless the volume must outlive the instance."
}
func (ltEBSDeleteOnTermination) Severity() ir.Severity { return ir.SeverityLow }
func (ltEBSDeleteOnTermination) AppliesTo(resType string) bool {
	return resType == "aws_launch_template"
}
func (ltEBSDeleteOnTermination) Check(r ir.Resource) []ir.Finding {
	mappings, _, present, known := getBlocks(r, "block_device_mappings")
	if !present || !known || len(mappings) == 0 {
		return nil
	}
	for _, m := range mappings {
		for _, ebs := range blockList(m, "ebs") {
			keep, span, p, k := blockBool(ebs, "delete_on_termination")
			if !p || !k || keep {
				continue
			}
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-697",
				Title:       (ltEBSDeleteOnTermination{}).Title(),
				Description: (ltEBSDeleteOnTermination{}).Description(),
				Severity:    ir.SeverityLow,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "block_device_mappings.ebs.delete_on_termination",
					Span:      evidenceSpan(span, r.Span),
					Actual:    "false",
					Expected:  "delete_on_termination = true",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-698: ASG with no scaling range (low)
// ---------------------------------------------------------------------------

type asgNoScalingRange struct{}

func (asgNoScalingRange) ID() string { return "AEGIS-AWS-698" }
func (asgNoScalingRange) Title() string {
	return "Auto scaling group with no scaling range"
}
func (asgNoScalingRange) Description() string {
	return "max_size equals min_size, so the group cannot scale at all: it " +
		"is a fixed fleet wearing an auto scaling group's name. Either " +
		"widen the range or replace it with plain instances."
}
func (asgNoScalingRange) Severity() ir.Severity { return ir.SeverityLow }
func (asgNoScalingRange) AppliesTo(resType string) bool {
	return resType == "aws_autoscaling_group"
}
func (asgNoScalingRange) Check(r ir.Resource) []ir.Finding {
	mn, _, mnPresent, mnKnown := getNumber(r, "min_size")
	mx, mxSpan, mxPresent, mxKnown := getNumber(r, "max_size")
	if !mnPresent || !mxPresent {
		return nil // cannot compare: sizes may come from elsewhere
	}
	if !mnKnown || !mxKnown {
		return nil // unresolved: cannot decide
	}
	if mn != mx {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-698",
		Title:       (asgNoScalingRange{}).Title(),
		Description: (asgNoScalingRange{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "max_size",
			Span:      evidenceSpan(mxSpan, r.Span),
			Actual:    "max_size == min_size (no scaling possible)",
			Expected:  "max_size > min_size",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-699: EC2 instance without Nitro Enclaves enabled (low)
// ---------------------------------------------------------------------------

type ec2NoNitroEnclaves struct{}

func (ec2NoNitroEnclaves) ID() string { return "AEGIS-AWS-699" }
func (ec2NoNitroEnclaves) Title() string {
	return "EC2 instance without Nitro Enclaves enabled"
}
func (ec2NoNitroEnclaves) Description() string {
	return "enclave_options is absent, so Nitro Enclaves are unavailable on " +
		"this instance. Workloads that process sensitive data should enable " +
		"enclave_options { enabled = true } to isolate it."
}
func (ec2NoNitroEnclaves) Severity() ir.Severity { return ir.SeverityLow }
func (ec2NoNitroEnclaves) AppliesTo(resType string) bool { return resType == "aws_instance" }
func (ec2NoNitroEnclaves) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "enclave_options")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		enabled, _, p, k := blockBool(blks[0], "enabled")
		if !p || !k {
			return nil // shape we cannot interpret: never fire
		}
		if enabled {
			return nil
		}
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-699",
			Title:       (ec2NoNitroEnclaves{}).Title(),
			Description: (ec2NoNitroEnclaves{}).Description(),
			Severity:    ir.SeverityLow,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "enclave_options.enabled",
				Span:      r.Span,
				Actual:    "false",
				Expected:  "enclave_options { enabled = true }",
			},
		}}
	}
	return absentInsecureDefault(ec2NoNitroEnclaves{}, r,
		"enclave_options",
		"absent (provider default: enclaves unavailable)",
		"enclave_options { enabled = true }")
}
