package aws

import (
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-391: EBS default encryption disabled
// ---------------------------------------------------------------------------

type ebsDefaultEncryptionDisabled struct{}

func (ebsDefaultEncryptionDisabled) ID() string { return "AEGIS-AWS-391" }
func (ebsDefaultEncryptionDisabled) Title() string {
	return "EBS default encryption disabled"
}
func (ebsDefaultEncryptionDisabled) Description() string {
	return "With default EBS encryption off, every new volume and snapshot " +
		"in the region is unencrypted unless each resource opts in."
}
func (ebsDefaultEncryptionDisabled) Severity() ir.Severity { return ir.SeverityMedium }

func (ebsDefaultEncryptionDisabled) AppliesTo(resType string) bool {
	return resType == "aws_ebs_encryption_by_default"
}

func (ebsDefaultEncryptionDisabled) Check(r ir.Resource) []ir.Finding {
	enabled, span, present, known := getBool(r, "enabled")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if enabled {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-391",
		Title:       (ebsDefaultEncryptionDisabled{}).Title(),
		Description: (ebsDefaultEncryptionDisabled{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-392: Backup vault without KMS
// ---------------------------------------------------------------------------

type backupVaultNoKMS struct{}

func (backupVaultNoKMS) ID() string { return "AEGIS-AWS-392" }
func (backupVaultNoKMS) Title() string {
	return "Backup vault without KMS encryption"
}
func (backupVaultNoKMS) Description() string {
	return "Recovery points in a vault without a customer-managed KMS key " +
		"rely on AWS-owned encryption, which cannot be audited or rotated " +
		"by the account."
}
func (backupVaultNoKMS) Severity() ir.Severity { return ir.SeverityMedium }

func (backupVaultNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_backup_vault"
}

func (backupVaultNoKMS) Check(r ir.Resource) []ir.Finding {
	key, span, present, known := getString(r, "kms_key_arn")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(key) != "" {
		return nil
	}
	actual := "absent"
	if present {
		actual = "empty"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-392",
		Title:       (backupVaultNoKMS{}).Title(),
		Description: (backupVaultNoKMS{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "kms_key_arn",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "customer-managed KMS key ARN",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-393: Config recorder disabled
// ---------------------------------------------------------------------------

type configRecorderDisabled struct{}

func (configRecorderDisabled) ID() string { return "AEGIS-AWS-393" }
func (configRecorderDisabled) Title() string {
	return "Config recorder not recording all resources"
}
func (configRecorderDisabled) Description() string {
	return "A configuration recorder with all_supported disabled leaves " +
		"resource types unmonitored, blinding drift detection and audit."
}
func (configRecorderDisabled) Severity() ir.Severity { return ir.SeverityMedium }

func (configRecorderDisabled) AppliesTo(resType string) bool {
	return resType == "aws_config_configuration_recorder"
}

func (configRecorderDisabled) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "recording_group")
	if !present || !known {
		// Absent block records all supported types by default.
		return nil
	}
	for _, b := range blks {
		v, ok := b["all_supported"]
		if !ok || !v.Known {
			continue // unresolved: cannot decide
		}
		if all, kok := v.AsBool(); kok && !all {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-393",
				Title:       (configRecorderDisabled{}).Title(),
				Description: (configRecorderDisabled{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "recording_group.all_supported",
					Span:      evidenceSpan(v.Span, span),
					Actual:    "false",
					Expected:  "true",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-394: Beanstalk without managed platform updates
// ---------------------------------------------------------------------------

type beanstalkNoManagedUpdates struct{}

func (beanstalkNoManagedUpdates) ID() string { return "AEGIS-AWS-394" }
func (beanstalkNoManagedUpdates) Title() string {
	return "Beanstalk environment without managed platform updates"
}
func (beanstalkNoManagedUpdates) Description() string {
	return "With managed platform updates explicitly disabled, the " +
		"environment never receives automatic security patches. Only an " +
		"explicit opt-out is flagged; absence of the setting is not judged."
}
func (beanstalkNoManagedUpdates) Severity() ir.Severity { return ir.SeverityMedium }

func (beanstalkNoManagedUpdates) AppliesTo(resType string) bool {
	return resType == "aws_elastic_beanstalk_environment"
}

func (beanstalkNoManagedUpdates) Check(r ir.Resource) []ir.Finding {
	settings, span, present, known := getBlocks(r, "setting")
	if !present || !known {
		return nil
	}
	for _, s := range settings {
		ns, _, _, nsKnown := blockString(s, "namespace")
		name, _, _, nameKnown := blockString(s, "name")
		val, vSpan, _, valKnown := blockString(s, "value")
		if !nsKnown || !nameKnown || !valKnown {
			continue
		}
		if ns == "aws:elasticbeanstalk:managedactions" &&
			name == "ManagedActionsEnabled" &&
			strings.EqualFold(strings.TrimSpace(val), "false") {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-394",
				Title:       (beanstalkNoManagedUpdates{}).Title(),
				Description: (beanstalkNoManagedUpdates{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "setting.value",
					Span:      evidenceSpan(vSpan, span),
					Actual:    "false (aws:elasticbeanstalk:managedactions / ManagedActionsEnabled)",
					Expected:  `"true"`,
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-395: App Runner service without KMS
// ---------------------------------------------------------------------------

type appRunnerNoKMS struct{}

func (appRunnerNoKMS) ID() string { return "AEGIS-AWS-395" }
func (appRunnerNoKMS) Title() string {
	return "App Runner service without customer-managed encryption"
}
func (appRunnerNoKMS) Description() string {
	return "An App Runner service without an encryption_configuration KMS " +
		"key stores service data under AWS-owned encryption only."
}
func (appRunnerNoKMS) Severity() ir.Severity { return ir.SeverityMedium }

func (appRunnerNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_apprunner_service"
}

func (appRunnerNoKMS) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "encryption_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		for _, b := range blks {
			key, _, _, keyKnown := blockString(b, "kms_key")
			if !keyKnown {
				return nil // unresolved: cannot decide
			}
			if strings.TrimSpace(key) != "" {
				return nil
			}
		}
	}
	actual := "encryption_configuration absent"
	if present {
		actual = "kms_key absent or empty"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-395",
		Title:       (appRunnerNoKMS{}).Title(),
		Description: (appRunnerNoKMS{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "encryption_configuration.kms_key",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "customer-managed KMS key",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-396: Default VPC in use
// ---------------------------------------------------------------------------

type defaultVPCInUse struct{}

func (defaultVPCInUse) ID() string { return "AEGIS-AWS-396" }
func (defaultVPCInUse) Title() string {
	return "Default VPC in use"
}
func (defaultVPCInUse) Description() string {
	return "Adopting the default VPC inherits AWS's permissive default " +
		"network layout. Production workloads should run in a custom VPC " +
		"with explicit subnets, route tables, and NACLs."
}
func (defaultVPCInUse) Severity() ir.Severity { return ir.SeverityMedium }

func (defaultVPCInUse) AppliesTo(resType string) bool {
	return resType == "aws_default_vpc"
}

func (defaultVPCInUse) Check(r ir.Resource) []ir.Finding {
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-396",
		Title:       (defaultVPCInUse{}).Title(),
		Description: (defaultVPCInUse{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "resource",
			Span:      r.Span,
			Actual:    "aws_default_vpc adopted",
			Expected:  "custom aws_vpc",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-397: Default security group with ingress rules
// ---------------------------------------------------------------------------

type defaultSGIngress struct{}

func (defaultSGIngress) ID() string { return "AEGIS-AWS-397" }
func (defaultSGIngress) Title() string {
	return "Default security group has ingress rules"
}
func (defaultSGIngress) Description() string {
	return "The default security group applies to every instance launched " +
		"without an explicit group. Any ingress rule on it widens the " +
		"blast radius of every future launch."
}
func (defaultSGIngress) Severity() ir.Severity { return ir.SeverityMedium }

func (defaultSGIngress) AppliesTo(resType string) bool {
	return resType == "aws_default_security_group"
}

func (defaultSGIngress) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "ingress")
	if !present || !known {
		return nil // empty or unresolved: nothing to flag
	}
	n := 0
	for range blks {
		n++
	}
	if n == 0 {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-397",
		Title:       (defaultSGIngress{}).Title(),
		Description: (defaultSGIngress{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "ingress",
			Span:      evidenceSpan(span, r.Span),
			Actual:    fmt.Sprintf("%d ingress rule(s) on the default security group", n),
			Expected:  "no ingress rules",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-398: VPC peering auto-accept enabled
// ---------------------------------------------------------------------------

type vpcPeeringAutoAccept struct{}

func (vpcPeeringAutoAccept) ID() string { return "AEGIS-AWS-398" }
func (vpcPeeringAutoAccept) Title() string {
	return "VPC peering connection auto-accept enabled"
}
func (vpcPeeringAutoAccept) Description() string {
	return "Auto-accepting peering requests removes the manual approval " +
		"step, so an unexpected peering can silently join the network."
}
func (vpcPeeringAutoAccept) Severity() ir.Severity { return ir.SeverityMedium }

func (vpcPeeringAutoAccept) AppliesTo(resType string) bool {
	return resType == "aws_vpc_peering_connection"
}

func (vpcPeeringAutoAccept) Check(r ir.Resource) []ir.Finding {
	auto, span, present, known := getBool(r, "auto_accept")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if !auto {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-398",
		Title:       (vpcPeeringAutoAccept{}).Title(),
		Description: (vpcPeeringAutoAccept{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "auto_accept",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (manual approval)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-399: RAM share allows external principals
// ---------------------------------------------------------------------------

type ramShareExternal struct{}

func (ramShareExternal) ID() string { return "AEGIS-AWS-399" }
func (ramShareExternal) Title() string {
	return "RAM resource share allows external principals"
}
func (ramShareExternal) Description() string {
	return "A resource share open to external principals can expose " +
		"subnets, license configurations, and other shared resources " +
		"outside the AWS organization."
}
func (ramShareExternal) Severity() ir.Severity { return ir.SeverityHigh }

func (ramShareExternal) AppliesTo(resType string) bool {
	return resType == "aws_ram_resource_share"
}

func (ramShareExternal) Check(r ir.Resource) []ir.Finding {
	ext, span, present, known := getBool(r, "allow_external_principals")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if !ext {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-399",
		Title:       (ramShareExternal{}).Title(),
		Description: (ramShareExternal{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "allow_external_principals",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-400: Default subnets in use
// ---------------------------------------------------------------------------

type defaultSubnetInUse struct{}

func (defaultSubnetInUse) ID() string { return "AEGIS-AWS-400" }
func (defaultSubnetInUse) Title() string {
	return "Default subnet in use"
}
func (defaultSubnetInUse) Description() string {
	return "Default subnets auto-assign public IPs and inherit the " +
		"default route table. Workloads should use explicit subnets with " +
		"controlled routing."
}
func (defaultSubnetInUse) Severity() ir.Severity { return ir.SeverityMedium }

func (defaultSubnetInUse) AppliesTo(resType string) bool {
	return resType == "aws_default_subnet"
}

func (defaultSubnetInUse) Check(r ir.Resource) []ir.Finding {
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-400",
		Title:       (defaultSubnetInUse{}).Title(),
		Description: (defaultSubnetInUse{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "resource",
			Span:      r.Span,
			Actual:    "aws_default_subnet adopted",
			Expected:  "custom aws_subnet",
		},
	}}
}

// GovernanceRules returns the governance & network-leftover rules, in ID order.
func GovernanceRules() []ir.Rule {
	return []ir.Rule{
		ebsDefaultEncryptionDisabled{}, // AEGIS-AWS-391
		backupVaultNoKMS{},             // AEGIS-AWS-392
		configRecorderDisabled{},       // AEGIS-AWS-393
		beanstalkNoManagedUpdates{},    // AEGIS-AWS-394
		appRunnerNoKMS{},               // AEGIS-AWS-395
		defaultVPCInUse{},              // AEGIS-AWS-396
		defaultSGIngress{},             // AEGIS-AWS-397
		vpcPeeringAutoAccept{},         // AEGIS-AWS-398
		ramShareExternal{},             // AEGIS-AWS-399
		defaultSubnetInUse{},           // AEGIS-AWS-400
	}
}
