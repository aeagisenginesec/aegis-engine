package aws

// Rule IDs covered in this file: AEGIS-AWS-301, AEGIS-AWS-302, AEGIS-AWS-304, AEGIS-AWS-305, AEGIS-AWS-307

import (
	"fmt"
	"testing"

	"aegis/internal/ir"
)

// mapVal wraps a block map as an ir.Value (for nested single-block attrs).
func mapVal(line int, m map[string]ir.Value) ir.Value {
	return ir.Value{Raw: m, Known: true, Span: spanAt(line)}
}

func TestComputeRulesIDOrder(t *testing.T) {
	got := ComputeRules()
	if len(got) != 10 {
		t.Fatalf("expected 10 compute rules, got %d", len(got))
	}
	for i, r := range got {
		want := fmt.Sprintf("AEGIS-AWS-%d", 301+i)
		if r.ID() != want {
			t.Fatalf("rule %d: want ID %s, got %s", i, want, r.ID())
		}
	}
}

// --- 301: launch template EBS unencrypted ---

func ebsMapping(line int, pairs ...any) map[string]ir.Value {
	return blk("ebs", mapVal(line, blk(pairs...)))
}

func Test301_UnencryptedFires(t *testing.T) {
	r := res("aws_launch_template", "web", map[string]ir.Value{
		"block_device_mappings": blks(3, ebsMapping(4, "encrypted", kv(false, 5))),
	})
	f := runRule(launchTemplateUnencryptedEBS{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "block_device_mappings.ebs.encrypted" {
		t.Fatalf("wrong evidence attribute: %+v", f[0].Evidence)
	}
}

func Test301_EncryptedQuiet(t *testing.T) {
	r := res("aws_launch_template", "web", map[string]ir.Value{
		"block_device_mappings": blks(3, ebsMapping(4, "encrypted", kv(true, 5))),
	})
	if f := runRule(launchTemplateUnencryptedEBS{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test301_AbsentEBSQuiet(t *testing.T) {
	// ebs map present without encrypted: provider default, not proven insecure.
	r := res("aws_launch_template", "web", map[string]ir.Value{
		"block_device_mappings": blks(3, blk("ebs", mapVal(4, blk()))),
	})
	if f := runRule(launchTemplateUnencryptedEBS{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test301_UnknownQuiet(t *testing.T) {
	r := res("aws_launch_template", "web", map[string]ir.Value{
		"block_device_mappings": blks(3, ebsMapping(4, "encrypted", ku(5))),
	})
	if f := runRule(launchTemplateUnencryptedEBS{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown, got %d", len(f))
	}
}

func Test301_NoMappingsQuiet(t *testing.T) {
	r := res("aws_launch_template", "web", map[string]ir.Value{})
	if f := runRule(launchTemplateUnencryptedEBS{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// --- 302: ECS privileged container ---

func Test302_PrivilegedFires(t *testing.T) {
	r := res("aws_ecs_task_definition", "app", map[string]ir.Value{
		"container_definitions": ks(`[{"name":"app","privileged":true}]`, 3),
	})
	f := runRule(ecsPrivilegedContainer{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
}

func Test302_NonPrivilegedQuiet(t *testing.T) {
	r := res("aws_ecs_task_definition", "app", map[string]ir.Value{
		"container_definitions": ks(`[{"name":"app","privileged":false},{"name":"side"}]`, 3),
	})
	if f := runRule(ecsPrivilegedContainer{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test302_UnparseableJSONQuiet(t *testing.T) {
	r := res("aws_ecs_task_definition", "app", map[string]ir.Value{
		"container_definitions": ks(`not json at all`, 3),
	})
	if f := runRule(ecsPrivilegedContainer{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unparseable JSON, got %d", len(f))
	}
}

func Test302_UnknownQuiet(t *testing.T) {
	r := res("aws_ecs_task_definition", "app", map[string]ir.Value{
		"container_definitions": ku(3),
	})
	if f := runRule(ecsPrivilegedContainer{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown, got %d", len(f))
	}
}

// --- 303: ECR without image scanning ---

func Test303_AbsentBlockFires(t *testing.T) {
	r := res("aws_ecr_repository", "app", map[string]ir.Value{})
	f := runRule(ecrNoImageScanning{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
}

func Test303_ScanOnPushQuiet(t *testing.T) {
	r := res("aws_ecr_repository", "app", map[string]ir.Value{
		"image_scanning_configuration": blks(3, blk("scan_on_push", kv(true, 4))),
	})
	if f := runRule(ecrNoImageScanning{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test303_ScanOffFires(t *testing.T) {
	r := res("aws_ecr_repository", "app", map[string]ir.Value{
		"image_scanning_configuration": blks(3, blk("scan_on_push", kv(false, 4))),
	})
	if f := runRule(ecrNoImageScanning{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test303_UnknownQuiet(t *testing.T) {
	r := res("aws_ecr_repository", "app", map[string]ir.Value{
		"image_scanning_configuration": blks(3, blk("scan_on_push", ku(4))),
	})
	if f := runRule(ecrNoImageScanning{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown, got %d", len(f))
	}
}

// --- 304: EKS without secrets encryption ---

func Test304_AbsentFires(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{})
	f := runRule(eksNoSecretsEncryption{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
}

func Test304_PresentQuiet(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{
		"encryption_config": blks(3, blk("resources", strList(4, "secrets"))),
	})
	if f := runRule(eksNoSecretsEncryption{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test304_UnknownBlockQuiet(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{
		"encryption_config": ir.Value{Known: false, Span: spanAt(3)},
	})
	if f := runRule(eksNoSecretsEncryption{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown block, got %d", len(f))
	}
}

// --- 305: EKS public endpoint ---

func Test305_PublicFires(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{
		"vpc_config": blks(3, blk("endpoint_public_access", kv(true, 4))),
	})
	f := runRule(eksPublicEndpoint{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
}

func Test305_PrivateQuiet(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{
		"vpc_config": blks(3, blk("endpoint_public_access", kv(false, 4))),
	})
	if f := runRule(eksPublicEndpoint{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test305_UnknownQuiet(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{
		"vpc_config": blks(3, blk("endpoint_public_access", ku(4))),
	})
	if f := runRule(eksPublicEndpoint{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown, got %d", len(f))
	}
}

func Test305_NoVPCConfigQuiet(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{})
	if f := runRule(eksPublicEndpoint{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// --- 306: EKS without control plane logging ---

func Test306_AbsentFires(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{})
	f := runRule(eksNoControlPlaneLogging{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
}

func Test306_EmptyListFires(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{
		"enabled_cluster_log_types": strList(3),
	})
	if f := runRule(eksNoControlPlaneLogging{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding for empty list, got %d", len(f))
	}
}

func Test306_EnabledQuiet(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{
		"enabled_cluster_log_types": strList(3, "api", "audit"),
	})
	if f := runRule(eksNoControlPlaneLogging{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test306_UnknownQuiet(t *testing.T) {
	r := res("aws_eks_cluster", "main", map[string]ir.Value{
		"enabled_cluster_log_types": ku(3),
	})
	if f := runRule(eksNoControlPlaneLogging{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown, got %d", len(f))
	}
}

// --- 307: Lambda env vars without KMS ---

func Test307_NoKMSFires(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"environment": blks(3, map[string]ir.Value{
			"variables": mapVal(5, map[string]ir.Value{"DB_PASSWORD": ks("secret", 6)}),
		}),
	})
	f := runRule(lambdaEnvNoKMS{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
}

func Test307_WithKMSQuiet(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"environment": blks(3, map[string]ir.Value{
			"variables":   mapVal(5, map[string]ir.Value{"DB_PASSWORD": ks("secret", 6)}),
			"kms_key_arn": ks("arn:aws:kms:us-east-1:123:key/abc", 7),
		}),
	})
	if f := runRule(lambdaEnvNoKMS{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test307_NoEnvironmentQuiet(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{})
	if f := runRule(lambdaEnvNoKMS{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test307_NoVariablesQuiet(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"environment": blks(3, map[string]ir.Value{}),
	})
	if f := runRule(lambdaEnvNoKMS{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for empty environment, got %d", len(f))
	}
}

func Test307_UnknownKMSQuiet(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"environment": blks(3, map[string]ir.Value{
			"variables":   mapVal(5, map[string]ir.Value{"DB_PASSWORD": ks("secret", 6)}),
			"kms_key_arn": ku(7),
		}),
	})
	if f := runRule(lambdaEnvNoKMS{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown KMS key, got %d", len(f))
	}
}

// --- 308: Lambda without active X-Ray tracing ---

func Test308_AbsentFires(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{})
	f := runRule(lambdaNoActiveTracing{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
}

func Test308_PassThroughFires(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"tracing_config": blks(3, blk("mode", ks("PassThrough", 4))),
	})
	if f := runRule(lambdaNoActiveTracing{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test308_ActiveQuiet(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"tracing_config": blks(3, blk("mode", ks("Active", 4))),
	})
	if f := runRule(lambdaNoActiveTracing{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test308_UnknownModeQuiet(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"tracing_config": blks(3, blk("mode", ku(4))),
	})
	if f := runRule(lambdaNoActiveTracing{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown mode, got %d", len(f))
	}
}

// --- 309: deprecated launch configuration ---

func Test309_Fires(t *testing.T) {
	r := res("aws_launch_configuration", "old", map[string]ir.Value{})
	if !(launchConfigurationDeprecated{}).AppliesTo("aws_launch_configuration") {
		t.Fatal("309 must apply to aws_launch_configuration")
	}
	f := runRule(launchConfigurationDeprecated{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
	if f[0].Resource != "aws_launch_configuration.old" {
		t.Fatalf("wrong resource: %s", f[0].Resource)
	}
}

func Test309_NotForLaunchTemplate(t *testing.T) {
	if (launchConfigurationDeprecated{}).AppliesTo("aws_launch_template") {
		t.Fatal("309 must not apply to aws_launch_template")
	}
}

// --- 310: EC2 without detailed monitoring ---

func Test310_AbsentFires(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{})
	f := runRule(ec2NoDetailedMonitoring{}, r)
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
	if got := f[0].Evidence.Actual; got != "absent (provider default: disabled)" {
		t.Fatalf("wrong actual: %q", got)
	}
}

func Test310_FalseFires(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{"monitoring": kv(false, 3)})
	if f := runRule(ec2NoDetailedMonitoring{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test310_TrueQuiet(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{"monitoring": kv(true, 3)})
	if f := runRule(ec2NoDetailedMonitoring{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func Test310_UnknownQuiet(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{"monitoring": ku(3)})
	if f := runRule(ec2NoDetailedMonitoring{}, r); len(f) != 0 {
		t.Fatalf("expected 0 findings for unknown, got %d", len(f))
	}
}
