package aws

// Rule IDs covered in this file: AEGIS-AWS-411, AEGIS-AWS-412, AEGIS-AWS-414, AEGIS-AWS-415, AEGIS-AWS-416, AEGIS-AWS-420

import (
	"testing"

	"aegis/internal/ir"
)

// --- 411: EC2 instance EBS volumes unencrypted ---

func Test411_UnencryptedEBSFires(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{
		"ebs_block_device": blks(4, blk("device_name", ks("/dev/sdf", 4), "encrypted", kv(false, 5))),
	})
	fs := runRule(ec2EBSBlockDeviceUnencrypted{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Evidence.Attribute != "ebs_block_device.encrypted" {
		t.Fatalf("wrong attribute: %s", fs[0].Evidence.Attribute)
	}
}

func Test411_EncryptedOK(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{
		"ebs_block_device": blks(4, blk("device_name", ks("/dev/sdf", 4), "encrypted", kv(true, 5))),
	})
	if fs := runRule(ec2EBSBlockDeviceUnencrypted{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test411_AbsentEncryptedOK(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{
		"ebs_block_device": blks(4, blk("device_name", ks("/dev/sdf", 4))),
	})
	if fs := runRule(ec2EBSBlockDeviceUnencrypted{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0 (provider default)", len(fs))
	}
}

func Test411_UnknownQuiet(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{
		"ebs_block_device": blks(4, blk("device_name", ks("/dev/sdf", 4), "encrypted", ku(5))),
	})
	if fs := runRule(ec2EBSBlockDeviceUnencrypted{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 412: ECS task definition with host networking ---

func Test412_HostNetworkFires(t *testing.T) {
	for _, mode := range []string{"host", "HOST"} {
		r := res("aws_ecs_task_definition", "app", map[string]ir.Value{
			"network_mode": ks(mode, 3),
		})
		if fs := runRule(ecsHostNetworking{}, r); len(fs) != 1 {
			t.Fatalf("mode=%q: got %d findings, want 1", mode, len(fs))
		}
	}
}

func Test412_AwsvpcOK(t *testing.T) {
	r := res("aws_ecs_task_definition", "app", map[string]ir.Value{
		"network_mode": ks("awsvpc", 3),
	})
	if fs := runRule(ecsHostNetworking{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test412_UnknownQuiet(t *testing.T) {
	r := res("aws_ecs_task_definition", "app", map[string]ir.Value{
		"network_mode": ku(3),
	})
	if fs := runRule(ecsHostNetworking{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 413: EKS node group with remote SSH access ---

func Test413_RemoteAccessFires(t *testing.T) {
	r := res("aws_eks_node_group", "workers", map[string]ir.Value{
		"remote_access": blks(5, blk("ec2_ssh_key", ks("my-key", 6))),
	})
	if fs := runRule(eksNodeGroupRemoteAccess{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test413_AbsentOK(t *testing.T) {
	r := res("aws_eks_node_group", "workers", map[string]ir.Value{})
	if fs := runRule(eksNodeGroupRemoteAccess{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test413_UnknownQuiet(t *testing.T) {
	r := res("aws_eks_node_group", "workers", map[string]ir.Value{
		"remote_access": ir.Value{Known: false, Span: spanAt(5)},
	})
	if fs := runRule(eksNodeGroupRemoteAccess{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 414: S3 account public access block disabled ---

func Test414_BlockPublicACLsFalseFires(t *testing.T) {
	r := res("aws_s3_account_public_access_block", "acct", map[string]ir.Value{
		"block_public_acls":   kv(false, 3),
		"block_public_policy": kv(true, 4),
	})
	fs := runRule(s3AccountPublicAccessBlockDisabled{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Evidence.Attribute != "block_public_acls" {
		t.Fatalf("wrong attribute: %s", fs[0].Evidence.Attribute)
	}
}

func Test414_BlockPublicPolicyFalseFires(t *testing.T) {
	r := res("aws_s3_account_public_access_block", "acct", map[string]ir.Value{
		"block_public_acls":   kv(true, 3),
		"block_public_policy": kv(false, 4),
	})
	if fs := runRule(s3AccountPublicAccessBlockDisabled{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test414_AllTrueOK(t *testing.T) {
	r := res("aws_s3_account_public_access_block", "acct", map[string]ir.Value{
		"block_public_acls":   kv(true, 3),
		"block_public_policy": kv(true, 4),
	})
	if fs := runRule(s3AccountPublicAccessBlockDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test414_UnknownQuiet(t *testing.T) {
	r := res("aws_s3_account_public_access_block", "acct", map[string]ir.Value{
		"block_public_acls": ku(3),
	})
	if fs := runRule(s3AccountPublicAccessBlockDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 415: EFS file system policy public ---

func Test415_PublicPolicyFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"elasticfilesystem:*"}]}`
	r := res("aws_efs_file_system_policy", "fs", map[string]ir.Value{
		"policy": ks(doc, 3),
	})
	if fs := runRule(efsFileSystemPolicyPublic{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test415_ScopedPolicyOK(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"elasticfilesystem:*"}]}`
	r := res("aws_efs_file_system_policy", "fs", map[string]ir.Value{
		"policy": ks(doc, 3),
	})
	if fs := runRule(efsFileSystemPolicyPublic{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test415_BadJSONQuiet(t *testing.T) {
	r := res("aws_efs_file_system_policy", "fs", map[string]ir.Value{
		"policy": ks("{{{ not json", 3),
	})
	if fs := runRule(efsFileSystemPolicyPublic{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 416: FSx OpenZFS unencrypted ---

func Test416_AbsentKeyFires(t *testing.T) {
	r := res("aws_fsx_openzfs_file_system", "fs", map[string]ir.Value{})
	if fs := runRule(fsxOpenZFSUnencrypted{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test416_KeySetOK(t *testing.T) {
	r := res("aws_fsx_openzfs_file_system", "fs", map[string]ir.Value{
		"kms_key_id": ks("arn:aws:kms:us-east-1:123:key/abc", 3),
	})
	if fs := runRule(fsxOpenZFSUnencrypted{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test416_UnknownQuiet(t *testing.T) {
	r := res("aws_fsx_openzfs_file_system", "fs", map[string]ir.Value{
		"kms_key_id": ku(3),
	})
	if fs := runRule(fsxOpenZFSUnencrypted{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 417: DynamoDB without deletion protection ---

func Test417_AbsentFires(t *testing.T) {
	r := res("aws_dynamodb_table", "data", map[string]ir.Value{})
	if fs := runRule(dynamoNoDeletionProtection{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test417_EnabledOK(t *testing.T) {
	r := res("aws_dynamodb_table", "data", map[string]ir.Value{
		"deletion_protection_enabled": kv(true, 3),
	})
	if fs := runRule(dynamoNoDeletionProtection{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test417_UnknownQuiet(t *testing.T) {
	r := res("aws_dynamodb_table", "data", map[string]ir.Value{
		"deletion_protection_enabled": ku(3),
	})
	if fs := runRule(dynamoNoDeletionProtection{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 418: OpenSearch advanced security disabled ---

// --- 419: Athena workgroup configuration not enforced ---

func Test419_NotEnforcedFires(t *testing.T) {
	r := res("aws_athena_workgroup", "wg", map[string]ir.Value{
		"enforce_workgroup_configuration": kv(false, 3),
	})
	if fs := runRule(athenaWorkgroupNotEnforced{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test419_EnforcedOK(t *testing.T) {
	r := res("aws_athena_workgroup", "wg", map[string]ir.Value{
		"enforce_workgroup_configuration": kv(true, 3),
	})
	if fs := runRule(athenaWorkgroupNotEnforced{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test419_UnknownQuiet(t *testing.T) {
	r := res("aws_athena_workgroup", "wg", map[string]ir.Value{
		"enforce_workgroup_configuration": ku(3),
	})
	if fs := runRule(athenaWorkgroupNotEnforced{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 420: KMS key policy public ---

func Test420_PublicPolicyFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*"}]}`
	r := res("aws_kms_key", "main", map[string]ir.Value{
		"policy": ks(doc, 3),
	})
	if fs := runRule(kmsKeyPolicyPublic{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test420_ScopedPolicyOK(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*"}]}`
	r := res("aws_kms_key", "main", map[string]ir.Value{
		"policy": ks(doc, 3),
	})
	if fs := runRule(kmsKeyPolicyPublic{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test420_UnknownQuiet(t *testing.T) {
	r := res("aws_kms_key", "main", map[string]ir.Value{
		"policy": ku(3),
	})
	if fs := runRule(kmsKeyPolicyPublic{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- registry ---

func TestData2Rules_IDOrder(t *testing.T) {
	rules := Data2Rules()
	// 418 removed in Sprint 2 (subset of AEGIS-AWS-523).
	want := []string{
		"AEGIS-AWS-411", "AEGIS-AWS-412", "AEGIS-AWS-413", "AEGIS-AWS-414",
		"AEGIS-AWS-415", "AEGIS-AWS-416", "AEGIS-AWS-417", "AEGIS-AWS-419",
		"AEGIS-AWS-420",
	}
	if len(rules) != len(want) {
		t.Fatalf("want %d rules, got %d", len(want), len(rules))
	}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Fatalf("index %d: want %s, got %s", i, want[i], r.ID())
		}
	}
}

func Test419_AbsentFires(t *testing.T) {
	// Absent enforce_workgroup_configuration: provider default is false.
	r := res("aws_athena_workgroup", "wg", map[string]ir.Value{})
	if fs := runRule(athenaWorkgroupNotEnforced{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}
