package aws

import (
	"strings"

	"aegis/internal/ir"
)

// Data2Rules returns the AEGIS-AWS-411..420 data & compute final rules in ID
// order. Wired into the pack by the parent; this file owns the 411-420 range.
func Data2Rules() []ir.Rule {
	return []ir.Rule{
		ec2EBSBlockDeviceUnencrypted{},
		ecsHostNetworking{},
		eksNodeGroupRemoteAccess{},
		s3AccountPublicAccessBlockDisabled{},
		efsFileSystemPolicyPublic{},
		fsxOpenZFSUnencrypted{},
		dynamoNoDeletionProtection{},
		opensearchNoAdvancedSecurity{},
		athenaWorkgroupNotEnforced{},
		kmsKeyPolicyPublic{},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-411: EC2 instance EBS volumes unencrypted
// ---------------------------------------------------------------------------

type ec2EBSBlockDeviceUnencrypted struct{}

func (ec2EBSBlockDeviceUnencrypted) ID() string { return "AEGIS-AWS-411" }
func (ec2EBSBlockDeviceUnencrypted) Title() string {
	return "EC2 instance EBS volumes unencrypted"
}
func (ec2EBSBlockDeviceUnencrypted) Description() string {
	return "An ebs_block_device entry in an aws_instance whose encrypted " +
		"attribute is false leaves the volume readable at rest. " +
		"(Known false only; absent follows the provider default.)"
}
func (ec2EBSBlockDeviceUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (ec2EBSBlockDeviceUnencrypted) AppliesTo(resType string) bool {
	return resType == "aws_instance"
}

func (ec2EBSBlockDeviceUnencrypted) Check(r ir.Resource) []ir.Finding {
	devices, _, present, known := getBlocks(r, "ebs_block_device")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, d := range devices {
		enc, espan, epresent, eknown := blockBool(d, "encrypted")
		if !epresent {
			continue // provider default: not proven insecure
		}
		if !eknown {
			return nil // unresolved: cannot decide
		}
		if !enc {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-411",
				Title:       (ec2EBSBlockDeviceUnencrypted{}).Title(),
				Description: (ec2EBSBlockDeviceUnencrypted{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "ebs_block_device.encrypted",
					Span:      evidenceSpan(espan, r.Span),
					Actual:    "false",
					Expected:  "encrypted = true",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-412: ECS task definition with host networking
// ---------------------------------------------------------------------------

type ecsHostNetworking struct{}

func (ecsHostNetworking) ID() string { return "AEGIS-AWS-412" }
func (ecsHostNetworking) Title() string {
	return "ECS task definition with host networking"
}
func (ecsHostNetworking) Description() string {
	return "network_mode = \"host\" gives containers full access to the host " +
		"network namespace, bypassing Docker network isolation."
}
func (ecsHostNetworking) Severity() ir.Severity { return ir.SeverityHigh }

func (ecsHostNetworking) AppliesTo(resType string) bool {
	return resType == "aws_ecs_task_definition"
}

func (ecsHostNetworking) Check(r ir.Resource) []ir.Finding {
	mode, span, present, known := getString(r, "network_mode")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(mode), "host") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-412",
		Title:       (ecsHostNetworking{}).Title(),
		Description: (ecsHostNetworking{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "network_mode",
			Span:      evidenceSpan(span, r.Span),
			Actual:    mode,
			Expected:  "awsvpc (or bridge) network mode",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-413: EKS node group with remote SSH access
// ---------------------------------------------------------------------------

type eksNodeGroupRemoteAccess struct{}

func (eksNodeGroupRemoteAccess) ID() string { return "AEGIS-AWS-413" }
func (eksNodeGroupRemoteAccess) Title() string {
	return "EKS node group with remote SSH access"
}
func (eksNodeGroupRemoteAccess) Description() string {
	return "A remote_access block on an aws_eks_node_group provisions SSH " +
		"key access to the worker nodes, widening the management plane."
}
func (eksNodeGroupRemoteAccess) Severity() ir.Severity { return ir.SeverityMedium }

func (eksNodeGroupRemoteAccess) AppliesTo(resType string) bool {
	return resType == "aws_eks_node_group"
}

func (eksNodeGroupRemoteAccess) Check(r ir.Resource) []ir.Finding {
	blocks, span, present, known := getBlocks(r, "remote_access")
	if !present {
		return nil // no SSH access configured
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if len(blocks) == 0 {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-413",
		Title:       (eksNodeGroupRemoteAccess{}).Title(),
		Description: (eksNodeGroupRemoteAccess{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "remote_access",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "remote_access block present (SSH into nodes)",
			Expected:  "no remote_access block (use SSM Session Manager)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-414: S3 account public access block disabled
// ---------------------------------------------------------------------------

type s3AccountPublicAccessBlockDisabled struct{}

func (s3AccountPublicAccessBlockDisabled) ID() string { return "AEGIS-AWS-414" }
func (s3AccountPublicAccessBlockDisabled) Title() string {
	return "S3 account public access block disabled"
}
func (s3AccountPublicAccessBlockDisabled) Description() string {
	return "The account-level aws_s3_account_public_access_block with " +
		"block_public_acls or block_public_policy set to false removes the " +
		"account-wide guardrail against public buckets."
}
func (s3AccountPublicAccessBlockDisabled) Severity() ir.Severity { return ir.SeverityHigh }

func (s3AccountPublicAccessBlockDisabled) AppliesTo(resType string) bool {
	return resType == "aws_s3_account_public_access_block"
}

func (s3AccountPublicAccessBlockDisabled) Check(r ir.Resource) []ir.Finding {
	weak := ""
	span := ir.Span{}
	for _, attr := range []string{"block_public_acls", "block_public_policy"} {
		val, aspan, present, known := getBool(r, attr)
		if !present {
			continue // default true: secure
		}
		if !known {
			return nil // unresolved: cannot decide
		}
		if !val {
			weak = attr
			span = aspan
			break
		}
	}
	if weak == "" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-414",
		Title:       (s3AccountPublicAccessBlockDisabled{}).Title(),
		Description: (s3AccountPublicAccessBlockDisabled{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: weak,
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  weak + " = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-415: EFS file system policy allows public principal
// ---------------------------------------------------------------------------

type efsFileSystemPolicyPublic struct{}

func (efsFileSystemPolicyPublic) ID() string { return "AEGIS-AWS-415" }
func (efsFileSystemPolicyPublic) Title() string {
	return "EFS file system policy allows public principal"
}
func (efsFileSystemPolicyPublic) Description() string {
	return "An Allow statement with Principal \"*\" in an EFS file system " +
		"policy grants anonymous access to the file system."
}
func (efsFileSystemPolicyPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (efsFileSystemPolicyPublic) AppliesTo(resType string) bool {
	return resType == "aws_efs_file_system_policy"
}

func (efsFileSystemPolicyPublic) Check(r ir.Resource) []ir.Finding {
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !policyAllowsPublicPrincipal(doc) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-415",
		Title:       (efsFileSystemPolicyPublic{}).Title(),
		Description: (efsFileSystemPolicyPublic{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "Allow with Principal \"*\"",
			Expected:  "no Allow statement with a public principal",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-416: FSx OpenZFS file system unencrypted
// ---------------------------------------------------------------------------

type fsxOpenZFSUnencrypted struct{}

func (fsxOpenZFSUnencrypted) ID() string { return "AEGIS-AWS-416" }
func (fsxOpenZFSUnencrypted) Title() string {
	return "FSx OpenZFS file system without customer-managed KMS key"
}
func (fsxOpenZFSUnencrypted) Description() string {
	return "An aws_fsx_openzfs_file_system without kms_key_id uses the " +
		"AWS-managed key, giving no customer control over key rotation or " +
		"revocation. (Attribute choice: kms_key_id is the documented " +
		"top-level argument on this resource for customer-managed keys.)"
}
func (fsxOpenZFSUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (fsxOpenZFSUnencrypted) AppliesTo(resType string) bool {
	return resType == "aws_fsx_openzfs_file_system"
}

func (fsxOpenZFSUnencrypted) Check(r ir.Resource) []ir.Finding {
	return kmsKeyAbsentFinding(fsxOpenZFSUnencrypted{}, r, "kms_key_id")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-417: DynamoDB table without deletion protection
// ---------------------------------------------------------------------------

type dynamoNoDeletionProtection struct{}

func (dynamoNoDeletionProtection) ID() string { return "AEGIS-AWS-417" }
func (dynamoNoDeletionProtection) Title() string {
	return "DynamoDB table without deletion protection"
}
func (dynamoNoDeletionProtection) Description() string {
	return "A DynamoDB table without deletion_protection_enabled can be " +
		"deleted by anyone with table-management permissions."
}
func (dynamoNoDeletionProtection) Severity() ir.Severity { return ir.SeverityMedium }

func (dynamoNoDeletionProtection) AppliesTo(resType string) bool {
	return resType == "aws_dynamodb_table"
}

func (dynamoNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "deletion_protection_enabled")
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-417",
			Title:       (dynamoNoDeletionProtection{}).Title(),
			Description: (dynamoNoDeletionProtection{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "deletion_protection_enabled",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent (provider default: disabled)",
				Expected:  "deletion_protection_enabled = true",
			},
		}}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-417",
		Title:       (dynamoNoDeletionProtection{}).Title(),
		Description: (dynamoNoDeletionProtection{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "deletion_protection_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "deletion_protection_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-418: OpenSearch advanced security disabled
// ---------------------------------------------------------------------------

type opensearchNoAdvancedSecurity struct{}

func (opensearchNoAdvancedSecurity) ID() string { return "AEGIS-AWS-418" }
func (opensearchNoAdvancedSecurity) Title() string {
	return "OpenSearch domain without advanced security"
}
func (opensearchNoAdvancedSecurity) Description() string {
	return "An OpenSearch domain without advanced_security_options (fine-" +
		"grained access control) cannot restrict index-level access."
}
func (opensearchNoAdvancedSecurity) Severity() ir.Severity { return ir.SeverityMedium }

func (opensearchNoAdvancedSecurity) AppliesTo(resType string) bool {
	return resType == "aws_opensearch_domain"
}

func (opensearchNoAdvancedSecurity) Check(r ir.Resource) []ir.Finding {
	return nestedEnabledCheck(r, "advanced_security_options",
		"AEGIS-AWS-418",
		(opensearchNoAdvancedSecurity{}).Title(),
		(opensearchNoAdvancedSecurity{}).Description(),
		ir.SeverityMedium,
		"absent (advanced security disabled)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-419: Athena workgroup configuration not enforced
// ---------------------------------------------------------------------------

type athenaWorkgroupNotEnforced struct{}

func (athenaWorkgroupNotEnforced) ID() string { return "AEGIS-AWS-419" }
func (athenaWorkgroupNotEnforced) Title() string {
	return "Athena workgroup configuration not enforced"
}
func (athenaWorkgroupNotEnforced) Description() string {
	return "With enforce_workgroup_configuration = false, queries can " +
		"override the workgroup's encryption and output settings, " +
		"bypassing its controls."
}
func (athenaWorkgroupNotEnforced) Severity() ir.Severity { return ir.SeverityMedium }

func (athenaWorkgroupNotEnforced) AppliesTo(resType string) bool {
	return resType == "aws_athena_workgroup"
}

func (athenaWorkgroupNotEnforced) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "enforce_workgroup_configuration")
	if !present {
		// Optional; the provider default is false: queries can override
		// the workgroup's encryption and output settings.
		return absentInsecureDefault(athenaWorkgroupNotEnforced{}, r,
			"enforce_workgroup_configuration", "absent (provider default: false)",
			"enforce_workgroup_configuration = true")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-419",
		Title:       (athenaWorkgroupNotEnforced{}).Title(),
		Description: (athenaWorkgroupNotEnforced{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enforce_workgroup_configuration",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "enforce_workgroup_configuration = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-420: KMS key policy allows public principal
// ---------------------------------------------------------------------------

type kmsKeyPolicyPublic struct{}

func (kmsKeyPolicyPublic) ID() string { return "AEGIS-AWS-420" }
func (kmsKeyPolicyPublic) Title() string {
	return "KMS key policy allows public principal"
}
func (kmsKeyPolicyPublic) Description() string {
	return "An Allow statement with Principal \"*\" in a KMS key policy " +
		"lets any AWS principal use the key."
}
func (kmsKeyPolicyPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (kmsKeyPolicyPublic) AppliesTo(resType string) bool {
	return resType == "aws_kms_key"
}

func (kmsKeyPolicyPublic) Check(r ir.Resource) []ir.Finding {
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !policyAllowsPublicPrincipal(doc) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-420",
		Title:       (kmsKeyPolicyPublic{}).Title(),
		Description: (kmsKeyPolicyPublic{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "Allow with Principal \"*\"",
			Expected:  "no Allow statement with a public principal",
		},
	}}
}
