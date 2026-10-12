package aws

// Rule IDs covered in this file: AEGIS-AWS-381, AEGIS-AWS-385, AEGIS-AWS-390

import (
	"fmt"
	"testing"

	"aegis/internal/ir"
)

func TestCompute2RulesIDOrder(t *testing.T) {
	rules := Compute2Rules()
	if len(rules) != 10 {
		t.Fatalf("expected 10 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := fmt.Sprintf("AEGIS-AWS-%d", 381+i)
		if r.ID() != want {
			t.Fatalf("rule %d: want ID %s, got %s", i, want, r.ID())
		}
	}
}

// --- 381 ---

func Test381_Fires(t *testing.T) {
	r := res("aws_ecs_service", "web", map[string]ir.Value{
		"network_configuration": blks(3, blk("assign_public_ip", kv(true, 4))),
	})
	if got := runRule(ecsServicePublicIP{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test381_PrivateQuiet(t *testing.T) {
	r := res("aws_ecs_service", "web", map[string]ir.Value{
		"network_configuration": blks(3, blk("assign_public_ip", kv(false, 4))),
	})
	if got := runRule(ecsServicePublicIP{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test381_UnknownQuiet(t *testing.T) {
	r := res("aws_ecs_service", "web", map[string]ir.Value{
		"network_configuration": blks(3, blk("assign_public_ip", ku(4))),
	})
	if got := runRule(ecsServicePublicIP{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 382 ---

func Test382_AbsentFires(t *testing.T) {
	r := res("aws_ecs_service", "web", map[string]ir.Value{})
	if got := runRule(ecsServiceNoCircuitBreaker{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test382_DisabledFires(t *testing.T) {
	r := res("aws_ecs_service", "web", map[string]ir.Value{
		"deployment_circuit_breaker": blks(3, blk("enable", kv(false, 4))),
	})
	if got := runRule(ecsServiceNoCircuitBreaker{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test382_EnabledQuiet(t *testing.T) {
	r := res("aws_ecs_service", "web", map[string]ir.Value{
		"deployment_circuit_breaker": blks(3, blk("enable", kv(true, 4))),
	})
	if got := runRule(ecsServiceNoCircuitBreaker{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 383 ---

func Test383_NoSettingsFires(t *testing.T) {
	r := res("aws_ecs_cluster", "main", map[string]ir.Value{})
	if got := runRule(ecsClusterNoContainerInsights{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test383_EnabledQuiet(t *testing.T) {
	r := res("aws_ecs_cluster", "main", map[string]ir.Value{
		"setting": blks(3, blk("name", ks("containerInsights", 4), "value", ks("enabled", 5))),
	})
	if got := runRule(ecsClusterNoContainerInsights{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test383_DisabledFires(t *testing.T) {
	r := res("aws_ecs_cluster", "main", map[string]ir.Value{
		"setting": blks(3, blk("name", ks("containerInsights", 4), "value", ks("disabled", 5))),
	})
	if got := runRule(ecsClusterNoContainerInsights{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test383_UnknownQuiet(t *testing.T) {
	r := res("aws_ecs_cluster", "main", map[string]ir.Value{
		"setting": blks(3, blk("name", ks("containerInsights", 4), "value", ku(5))),
	})
	if got := runRule(ecsClusterNoContainerInsights{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 384 ---

func Test384_Fires(t *testing.T) {
	r := res("aws_codebuild_project", "build", map[string]ir.Value{
		"artifacts": blks(3, blk("encryption_disabled", kv(true, 4))),
	})
	if got := runRule(codebuildArtifactsNoEncryption{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test384_EnabledQuiet(t *testing.T) {
	r := res("aws_codebuild_project", "build", map[string]ir.Value{
		"artifacts": blks(3, blk("encryption_disabled", kv(false, 4))),
	})
	if got := runRule(codebuildArtifactsNoEncryption{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test384_UnknownQuiet(t *testing.T) {
	r := res("aws_codebuild_project", "build", map[string]ir.Value{
		"artifacts": blks(3, blk("encryption_disabled", ku(4))),
	})
	if got := runRule(codebuildArtifactsNoEncryption{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 385 ---

func Test385_Fires(t *testing.T) {
	r := res("aws_codebuild_project", "build", map[string]ir.Value{
		"environment": blks(3, blk("privileged_mode", kv(true, 4))),
	})
	if got := runRule(codebuildPrivilegedMode{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test385_Quiet(t *testing.T) {
	r := res("aws_codebuild_project", "build", map[string]ir.Value{
		"environment": blks(3, blk("privileged_mode", kv(false, 4))),
	})
	if got := runRule(codebuildPrivilegedMode{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test385_UnknownQuiet(t *testing.T) {
	r := res("aws_codebuild_project", "build", map[string]ir.Value{
		"environment": blks(3, blk("privileged_mode", ku(4))),
	})
	if got := runRule(codebuildPrivilegedMode{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 386 ---

func Test386_NoKeyFires(t *testing.T) {
	r := res("aws_codepipeline", "pipe", map[string]ir.Value{
		"artifact_store": blks(3, blk("location", ks("bucket", 4), "type", ks("S3", 5))),
	})
	if got := runRule(codepipelineArtifactStoreNoKMS{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test386_WithKeyQuiet(t *testing.T) {
	r := res("aws_codepipeline", "pipe", map[string]ir.Value{
		"artifact_store": blks(3, blk(
			"encryption_key", blks(4, blk("id", ks("arn:aws:kms:x", 5), "type", ks("KMS", 6))),
		)),
	})
	if got := runRule(codepipelineArtifactStoreNoKMS{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test386_NoStoreQuiet(t *testing.T) {
	r := res("aws_codepipeline", "pipe", map[string]ir.Value{})
	if got := runRule(codepipelineArtifactStoreNoKMS{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 387 ---

func Test387_AbsentFires(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{})
	if got := runRule(cognitoNoMFA{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test387_OffFires(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"mfa_configuration": ks("OFF", 3),
	})
	if got := runRule(cognitoNoMFA{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test387_OnQuiet(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"mfa_configuration": ks("ON", 3),
	})
	if got := runRule(cognitoNoMFA{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test387_UnknownQuiet(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"mfa_configuration": ku(3),
	})
	if got := runRule(cognitoNoMFA{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 388 ---

func Test388_AbsentMinLengthFires(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"password_policy": blks(3, blk("require_lowercase", kv(true, 4))),
	})
	if got := runRule(cognitoWeakPasswordPolicy{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test388_ShortFires(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"password_policy": blks(3, blk("minimum_length", kn(6, 4))),
	})
	got := runRule(cognitoWeakPasswordPolicy{}, r)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Evidence.Actual != "6" {
		t.Fatalf("wrong actual: %q", got[0].Evidence.Actual)
	}
}

func Test388_StrongQuiet(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"password_policy": blks(3, blk("minimum_length", kn(12, 4))),
	})
	if got := runRule(cognitoWeakPasswordPolicy{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test388_UnknownQuiet(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"password_policy": blks(3, blk("minimum_length", ku(4))),
	})
	if got := runRule(cognitoWeakPasswordPolicy{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test388_NoPolicyBlockQuiet(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{})
	if got := runRule(cognitoWeakPasswordPolicy{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 389 ---

func Test389_AbsentFires(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{})
	if got := runRule(cognitoAdvancedSecurityOff{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test389_OffFires(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"user_pool_add_ons": blks(3, blk("advanced_security_mode", ks("OFF", 4))),
	})
	if got := runRule(cognitoAdvancedSecurityOff{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test389_EnforcedQuiet(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"user_pool_add_ons": blks(3, blk("advanced_security_mode", ks("ENFORCED", 4))),
	})
	if got := runRule(cognitoAdvancedSecurityOff{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test389_UnknownQuiet(t *testing.T) {
	r := res("aws_cognito_user_pool", "pool", map[string]ir.Value{
		"user_pool_add_ons": blks(3, blk("advanced_security_mode", ku(4))),
	})
	if got := runRule(cognitoAdvancedSecurityOff{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

// --- 390 ---

const iotAdminPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

func Test390_Fires(t *testing.T) {
	r := res("aws_iot_policy", "broad", map[string]ir.Value{
		"policy": ks(iotAdminPolicy, 3),
	})
	if got := runRule(iotPolicyOverlyBroad{}, r); len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func Test390_ScopedQuiet(t *testing.T) {
	pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iot:Connect","Resource":"arn:aws:iot:*:123:client/*"}]}`
	r := res("aws_iot_policy", "scoped", map[string]ir.Value{
		"policy": ks(pol, 3),
	})
	if got := runRule(iotPolicyOverlyBroad{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test390_BadJSONQuiet(t *testing.T) {
	r := res("aws_iot_policy", "broken", map[string]ir.Value{
		"policy": ks("{not json", 3),
	})
	if got := runRule(iotPolicyOverlyBroad{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func Test390_UnknownQuiet(t *testing.T) {
	r := res("aws_iot_policy", "unk", map[string]ir.Value{
		"policy": ku(3),
	})
	if got := runRule(iotPolicyOverlyBroad{}, r); len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}
