package aws

import (
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// Compute2Rules returns the AEGIS-AWS-381..390 compute-plus rules in ID
// order. Wired into the pack by the parent; this file owns the 381-390 range.
func Compute2Rules() []ir.Rule {
	return []ir.Rule{
		ecsServicePublicIP{},
		ecsServiceNoCircuitBreaker{},
		ecsClusterNoContainerInsights{},
		codebuildArtifactsNoEncryption{},
		codebuildPrivilegedMode{},
		codepipelineArtifactStoreNoKMS{},
		cognitoNoMFA{},
		cognitoWeakPasswordPolicy{},
		cognitoAdvancedSecurityOff{},
		iotPolicyOverlyBroad{},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-381: ECS service with public IP
// ---------------------------------------------------------------------------

type ecsServicePublicIP struct{}

func (ecsServicePublicIP) ID() string { return "AEGIS-AWS-381" }
func (ecsServicePublicIP) Title() string {
	return "ECS service with public IP assignment"
}
func (ecsServicePublicIP) Description() string {
	return "An aws_ecs_service whose network_configuration sets " +
		"assign_public_ip = true exposes tasks directly to the internet. " +
		"Services should run behind a load balancer in private subnets."
}
func (ecsServicePublicIP) Severity() ir.Severity { return ir.SeverityHigh }

func (ecsServicePublicIP) AppliesTo(resType string) bool {
	return resType == "aws_ecs_service"
}

func (ecsServicePublicIP) Check(r ir.Resource) []ir.Finding {
	nets, _, present, known := getBlocks(r, "network_configuration")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, n := range nets {
		pub, pspan, ppresent, pknown := blockBool(n, "assign_public_ip")
		if !ppresent || !pknown {
			continue
		}
		if pub {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-381",
				Title:       (ecsServicePublicIP{}).Title(),
				Description: (ecsServicePublicIP{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "network_configuration.assign_public_ip",
					Span:      evidenceSpan(pspan, r.Span),
					Actual:    "true",
					Expected:  "false (tasks in private subnets)",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-382: ECS service without deployment circuit breaker
// ---------------------------------------------------------------------------

type ecsServiceNoCircuitBreaker struct{}

func (ecsServiceNoCircuitBreaker) ID() string { return "AEGIS-AWS-382" }
func (ecsServiceNoCircuitBreaker) Title() string {
	return "ECS service without deployment circuit breaker"
}
func (ecsServiceNoCircuitBreaker) Description() string {
	return "An aws_ecs_service without deployment_circuit_breaker (or with " +
		"enable = false) keeps rolling back broken deployments instead of " +
		"failing fast, letting bad tasks replace healthy ones."
}
func (ecsServiceNoCircuitBreaker) Severity() ir.Severity { return ir.SeverityMedium }

func (ecsServiceNoCircuitBreaker) AppliesTo(resType string) bool {
	return resType == "aws_ecs_service"
}

func (ecsServiceNoCircuitBreaker) Check(r ir.Resource) []ir.Finding {
	mk := func(span ir.Span, actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-382",
			Title:       (ecsServiceNoCircuitBreaker{}).Title(),
			Description: (ecsServiceNoCircuitBreaker{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "deployment_circuit_breaker.enable",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "enable = true",
			},
		}}
	}
	cbs, _, present, known := getBlocks(r, "deployment_circuit_breaker")
	if !present {
		return mk(ir.Span{}, "absent (provider default: disabled)")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	for _, cb := range cbs {
		en, espan, epresent, eknown := blockBool(cb, "enable")
		if !epresent {
			return mk(espan, "absent (defaults to false)")
		}
		if !eknown {
			return nil
		}
		if !en {
			return mk(espan, "false")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-383: ECS cluster without Container Insights
// ---------------------------------------------------------------------------

type ecsClusterNoContainerInsights struct{}

func (ecsClusterNoContainerInsights) ID() string { return "AEGIS-AWS-383" }
func (ecsClusterNoContainerInsights) Title() string {
	return "ECS cluster without Container Insights"
}
func (ecsClusterNoContainerInsights) Description() string {
	return "An aws_ecs_cluster with no setting enabling containerInsights " +
		"lacks CloudWatch Container Insights metrics, weakening detection " +
		"of anomalous task behavior."
}
func (ecsClusterNoContainerInsights) Severity() ir.Severity { return ir.SeverityMedium }

func (ecsClusterNoContainerInsights) AppliesTo(resType string) bool {
	return resType == "aws_ecs_cluster"
}

func (ecsClusterNoContainerInsights) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := getBlocks(r, "setting")
	if !present {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-383",
			Title:       (ecsClusterNoContainerInsights{}).Title(),
			Description: (ecsClusterNoContainerInsights{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "setting",
				Span:      r.Span,
				Actual:    "absent (Container Insights disabled by default)",
				Expected:  "setting { name = \"containerInsights\", value = \"enabled\" }",
			},
		}}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	for _, s := range settings {
		name, _, npresent, nknown := blockString(s, "name")
		val, _, vpresent, vknown := blockString(s, "value")
		if !npresent || !nknown || !vpresent || !vknown {
			return nil // partially unresolved: cannot decide
		}
		if strings.EqualFold(strings.TrimSpace(name), "containerInsights") &&
			strings.EqualFold(strings.TrimSpace(val), "enabled") {
			return nil
		}
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-383",
		Title:       (ecsClusterNoContainerInsights{}).Title(),
		Description: (ecsClusterNoContainerInsights{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "setting",
			Span:      r.Span,
			Actual:    "no containerInsights=enabled setting",
			Expected:  "setting { name = \"containerInsights\", value = \"enabled\" }",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-384: CodeBuild artifacts encryption disabled
// ---------------------------------------------------------------------------

type codebuildArtifactsNoEncryption struct{}

func (codebuildArtifactsNoEncryption) ID() string { return "AEGIS-AWS-384" }
func (codebuildArtifactsNoEncryption) Title() string {
	return "CodeBuild project with artifacts encryption disabled"
}
func (codebuildArtifactsNoEncryption) Description() string {
	return "An aws_codebuild_project whose artifacts block sets " +
		"encryption_disabled = true stores build outputs unencrypted in S3."
}
func (codebuildArtifactsNoEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (codebuildArtifactsNoEncryption) AppliesTo(resType string) bool {
	return resType == "aws_codebuild_project"
}

func (codebuildArtifactsNoEncryption) Check(r ir.Resource) []ir.Finding {
	arts, _, present, known := getBlocks(r, "artifacts")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, a := range arts {
		dis, dspan, dpresent, dknown := blockBool(a, "encryption_disabled")
		if !dpresent || !dknown {
			continue
		}
		if dis {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-384",
				Title:       (codebuildArtifactsNoEncryption{}).Title(),
				Description: (codebuildArtifactsNoEncryption{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "artifacts.encryption_disabled",
					Span:      evidenceSpan(dspan, r.Span),
					Actual:    "true",
					Expected:  "false or omitted (encryption enabled)",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-385: CodeBuild privileged mode
// ---------------------------------------------------------------------------

type codebuildPrivilegedMode struct{}

func (codebuildPrivilegedMode) ID() string { return "AEGIS-AWS-385" }
func (codebuildPrivilegedMode) Title() string {
	return "CodeBuild project with privileged mode"
}
func (codebuildPrivilegedMode) Description() string {
	return "An aws_codebuild_project with privileged_mode = true runs " +
		"Docker-in-Docker, giving build containers elevated privileges " +
		"that a compromised build can abuse."
}
func (codebuildPrivilegedMode) Severity() ir.Severity { return ir.SeverityHigh }

func (codebuildPrivilegedMode) AppliesTo(resType string) bool {
	return resType == "aws_codebuild_project"
}

func (codebuildPrivilegedMode) Check(r ir.Resource) []ir.Finding {
	envs, _, present, known := getBlocks(r, "environment")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, e := range envs {
		priv, pspan, ppresent, pknown := blockBool(e, "privileged_mode")
		if !ppresent || !pknown {
			continue
		}
		if priv {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-385",
				Title:       (codebuildPrivilegedMode{}).Title(),
				Description: (codebuildPrivilegedMode{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "environment.privileged_mode",
					Span:      evidenceSpan(pspan, r.Span),
					Actual:    "true",
					Expected:  "false",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-386: CodePipeline artifact store without KMS
// ---------------------------------------------------------------------------

type codepipelineArtifactStoreNoKMS struct{}

func (codepipelineArtifactStoreNoKMS) ID() string { return "AEGIS-AWS-386" }
func (codepipelineArtifactStoreNoKMS) Title() string {
	return "CodePipeline artifact store without KMS encryption"
}
func (codepipelineArtifactStoreNoKMS) Description() string {
	return "An aws_codepipeline whose artifact_store has no encryption_key " +
		"block relies on the default S3 key instead of a customer-managed " +
		"key for pipeline artifacts."
}
func (codepipelineArtifactStoreNoKMS) Severity() ir.Severity { return ir.SeverityMedium }

func (codepipelineArtifactStoreNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_codepipeline"
}

func (codepipelineArtifactStoreNoKMS) Check(r ir.Resource) []ir.Finding {
	stores, _, present, known := getBlocks(r, "artifact_store")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, s := range stores {
		if blockList(s, "encryption_key") == nil {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-386",
				Title:       (codepipelineArtifactStoreNoKMS{}).Title(),
				Description: (codepipelineArtifactStoreNoKMS{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "artifact_store.encryption_key",
					Span:      r.Span,
					Actual:    "absent",
					Expected:  "encryption_key { id = <kms-key-arn>, type = \"KMS\" }",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-387: Cognito user pool without MFA
// ---------------------------------------------------------------------------

type cognitoNoMFA struct{}

func (cognitoNoMFA) ID() string { return "AEGIS-AWS-387" }
func (cognitoNoMFA) Title() string {
	return "Cognito user pool without MFA"
}
func (cognitoNoMFA) Description() string {
	return "An aws_cognito_user_pool with mfa_configuration absent or OFF " +
		"lets users authenticate with passwords alone."
}
func (cognitoNoMFA) Severity() ir.Severity { return ir.SeverityMedium }

func (cognitoNoMFA) AppliesTo(resType string) bool {
	return resType == "aws_cognito_user_pool"
}

func (cognitoNoMFA) Check(r ir.Resource) []ir.Finding {
	mk := func(span ir.Span, actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-387",
			Title:       (cognitoNoMFA{}).Title(),
			Description: (cognitoNoMFA{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "mfa_configuration",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "ON or OPTIONAL",
			},
		}}
	}
	mfa, mspan, present, known := getString(r, "mfa_configuration")
	if !present {
		return mk(ir.Span{}, "absent (provider default: OFF)")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(mfa), "OFF") {
		return mk(mspan, "OFF")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-388: Cognito user pool weak password policy
// ---------------------------------------------------------------------------

type cognitoWeakPasswordPolicy struct{}

func (cognitoWeakPasswordPolicy) ID() string { return "AEGIS-AWS-388" }
func (cognitoWeakPasswordPolicy) Title() string {
	return "Cognito user pool with weak password policy"
}
func (cognitoWeakPasswordPolicy) Description() string {
	return "An aws_cognito_user_pool whose password_policy has " +
		"minimum_length below 8 (or omits it) permits weak passwords."
}
func (cognitoWeakPasswordPolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (cognitoWeakPasswordPolicy) AppliesTo(resType string) bool {
	return resType == "aws_cognito_user_pool"
}

func (cognitoWeakPasswordPolicy) Check(r ir.Resource) []ir.Finding {
	pols, _, present, known := getBlocks(r, "password_policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, p := range pols {
		min, mspan, mpresent, mknown := blockNumber(p, "minimum_length")
		if !mpresent {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-388",
				Title:       (cognitoWeakPasswordPolicy{}).Title(),
				Description: (cognitoWeakPasswordPolicy{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "password_policy.minimum_length",
					Span:      r.Span,
					Actual:    "absent",
					Expected:  "minimum_length >= 8",
				},
			}}
		}
		if !mknown {
			return nil // unresolved: cannot decide
		}
		if min < 8 {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-388",
				Title:       (cognitoWeakPasswordPolicy{}).Title(),
				Description: (cognitoWeakPasswordPolicy{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "password_policy.minimum_length",
					Span:      evidenceSpan(mspan, r.Span),
					Actual:    strconv.FormatFloat(min, 'f', -1, 64), Expected: "minimum_length >= 8",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-389: Cognito advanced security off
// ---------------------------------------------------------------------------

type cognitoAdvancedSecurityOff struct{}

func (cognitoAdvancedSecurityOff) ID() string { return "AEGIS-AWS-389" }
func (cognitoAdvancedSecurityOff) Title() string {
	return "Cognito user pool without advanced security enforcement"
}
func (cognitoAdvancedSecurityOff) Description() string {
	return "An aws_cognito_user_pool whose user_pool_add_ons block is absent " +
		"or whose advanced_security_mode is not ENFORCED misses " +
		"compromised-credential and adaptive-authentication checks."
}
func (cognitoAdvancedSecurityOff) Severity() ir.Severity { return ir.SeverityMedium }

func (cognitoAdvancedSecurityOff) AppliesTo(resType string) bool {
	return resType == "aws_cognito_user_pool"
}

func (cognitoAdvancedSecurityOff) Check(r ir.Resource) []ir.Finding {
	mk := func(span ir.Span, actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-389",
			Title:       (cognitoAdvancedSecurityOff{}).Title(),
			Description: (cognitoAdvancedSecurityOff{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "user_pool_add_ons.advanced_security_mode",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "ENFORCED",
			},
		}}
	}
	addons, _, present, known := getBlocks(r, "user_pool_add_ons")
	if !present {
		return mk(ir.Span{}, "absent (advanced security off by default)")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	for _, a := range addons {
		mode, mspan, mpresent, mknown := blockString(a, "advanced_security_mode")
		if !mpresent {
			return mk(mspan, "absent")
		}
		if !mknown {
			return nil
		}
		if !strings.EqualFold(strings.TrimSpace(mode), "ENFORCED") {
			return mk(mspan, mode)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-390: IoT policy overly broad
// ---------------------------------------------------------------------------

type iotPolicyOverlyBroad struct{}

func (iotPolicyOverlyBroad) ID() string { return "AEGIS-AWS-390" }
func (iotPolicyOverlyBroad) Title() string {
	return "IoT policy with overly broad Allow statement"
}
func (iotPolicyOverlyBroad) Description() string {
	return "An aws_iot_policy with an Allow statement granting Action " +
		"\"*\" (or \"*:*\") on Resource \"*\" gives every attached device " +
		"full control over the IoT fleet."
}
func (iotPolicyOverlyBroad) Severity() ir.Severity { return ir.SeverityHigh }

func (iotPolicyOverlyBroad) AppliesTo(resType string) bool {
	return resType == "aws_iot_policy"
}

func (iotPolicyOverlyBroad) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if inlinePolicyIsAdmin(pol) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-390",
			Title:       (iotPolicyOverlyBroad{}).Title(),
			Description: (iotPolicyOverlyBroad{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "Allow statement with Action \"*\" (or \"*:*\") on Resource \"*\"",
				Expected:  "scoped Action and Resource lists",
			},
		}}
	}
	return nil
}
