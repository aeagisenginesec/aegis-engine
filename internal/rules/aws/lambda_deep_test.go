package aws

import (
	"testing"

	"aegis/internal/ir"
)

func intVal(n int, line int) ir.Value {
	return ir.Value{Raw: n, Known: true, Span: spanAt(line)}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-720
// ---------------------------------------------------------------------------

func TestLambdaEventInvokeNoDestinationFires(t *testing.T) {
	f := runRule(lambdaEventInvokeNoDestination{},
		res("aws_lambda_function_event_invoke_config", "c", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-720" {
		t.Fatalf("expected 1 finding for 720, got %d", len(f))
	}
}

func TestLambdaEventInvokeNoDestinationQuiet(t *testing.T) {
	f := runRule(lambdaEventInvokeNoDestination{},
		res("aws_lambda_function_event_invoke_config", "c", map[string]ir.Value{
			"destination_config": blks(3, blk("on_failure", blks(4, blk()))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestLambdaEventInvokeNoDestinationUnknownQuiet(t *testing.T) {
	f := runRule(lambdaEventInvokeNoDestination{},
		res("aws_lambda_function_event_invoke_config", "c", map[string]ir.Value{
			"destination_config": ku(3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-721
// ---------------------------------------------------------------------------

func TestLambdaImageMutableTagLatestFires(t *testing.T) {
	f := runRule(lambdaImageMutableTag{},
		res("aws_lambda_function", "f", map[string]ir.Value{
			"image_uri": ks("123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest", 3),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-721" {
		t.Fatalf("expected 1 finding for 721, got %d", len(f))
	}
}

func TestLambdaImageMutableTagNoDigestFires(t *testing.T) {
	f := runRule(lambdaImageMutableTag{},
		res("aws_lambda_function", "f", map[string]ir.Value{
			"image_uri": ks("123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1.2.3", 3),
		}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestLambdaImageMutableTagDigestQuiet(t *testing.T) {
	f := runRule(lambdaImageMutableTag{},
		res("aws_lambda_function", "f", map[string]ir.Value{
			"image_uri": ks("123456789012.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc123", 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestLambdaImageMutableTagUnknownQuiet(t *testing.T) {
	f := runRule(lambdaImageMutableTag{},
		res("aws_lambda_function", "f", map[string]ir.Value{"image_uri": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-722
// ---------------------------------------------------------------------------

func TestLambdaTimeoutLongFires(t *testing.T) {
	f := runRule(lambdaTimeoutLong{},
		res("aws_lambda_function", "f", map[string]ir.Value{"timeout": intVal(600, 3)}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-722" {
		t.Fatalf("expected 1 finding for 722, got %d", len(f))
	}
}

func TestLambdaTimeoutLongQuiet(t *testing.T) {
	f := runRule(lambdaTimeoutLong{},
		res("aws_lambda_function", "f", map[string]ir.Value{"timeout": intVal(60, 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestLambdaTimeoutLongUnknownQuiet(t *testing.T) {
	f := runRule(lambdaTimeoutLong{},
		res("aws_lambda_function", "f", map[string]ir.Value{"timeout": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-723
// ---------------------------------------------------------------------------

func TestLambdaAliasLatestVersionFires(t *testing.T) {
	f := runRule(lambdaAliasLatestVersion{},
		res("aws_lambda_alias", "a", map[string]ir.Value{"function_version": ks("$LATEST", 3)}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-723" {
		t.Fatalf("expected 1 finding for 723, got %d", len(f))
	}
}

func TestLambdaAliasLatestVersionQuiet(t *testing.T) {
	f := runRule(lambdaAliasLatestVersion{},
		res("aws_lambda_alias", "a", map[string]ir.Value{"function_version": ks("7", 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestLambdaAliasLatestVersionUnknownQuiet(t *testing.T) {
	f := runRule(lambdaAliasLatestVersion{},
		res("aws_lambda_alias", "a", map[string]ir.Value{"function_version": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-724
// ---------------------------------------------------------------------------

func TestLambdaPermissionNoSourceArnFires(t *testing.T) {
	f := runRule(lambdaPermissionNoSourceArn{},
		res("aws_lambda_permission", "p", map[string]ir.Value{
			"principal": ks("s3.amazonaws.com", 3),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-724" {
		t.Fatalf("expected 1 finding for 724, got %d", len(f))
	}
}

func TestLambdaPermissionNoSourceArnQuiet(t *testing.T) {
	f := runRule(lambdaPermissionNoSourceArn{},
		res("aws_lambda_permission", "p", map[string]ir.Value{
			"principal":  ks("s3.amazonaws.com", 3),
			"source_arn": ks("arn:aws:s3:::my-bucket", 4),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestLambdaPermissionNoSourceArnNonServiceQuiet(t *testing.T) {
	f := runRule(lambdaPermissionNoSourceArn{},
		res("aws_lambda_permission", "p", map[string]ir.Value{
			"principal": ks("123456789012", 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-725
// ---------------------------------------------------------------------------

func TestCodeSigningWarnOnViolationFires(t *testing.T) {
	f := runRule(codeSigningWarnOnViolation{},
		res("aws_lambda_code_signing_config", "c", map[string]ir.Value{
			"policies": blks(3, blk("untrusted_artifact_on_violation", ks("Warn", 4))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-725" {
		t.Fatalf("expected 1 finding for 725, got %d", len(f))
	}
}

func TestCodeSigningWarnOnViolationAbsentFires(t *testing.T) {
	f := runRule(codeSigningWarnOnViolation{},
		res("aws_lambda_code_signing_config", "c", map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestCodeSigningWarnOnViolationQuiet(t *testing.T) {
	f := runRule(codeSigningWarnOnViolation{},
		res("aws_lambda_code_signing_config", "c", map[string]ir.Value{
			"policies": blks(3, blk("untrusted_artifact_on_violation", ks("Enforce", 4))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-726
// ---------------------------------------------------------------------------

func TestLambdaS3UnpinnedObjectFires(t *testing.T) {
	f := runRule(lambdaS3UnpinnedObject{},
		res("aws_lambda_function", "f", map[string]ir.Value{
			"s3_bucket": ks("my-bucket", 3),
			"s3_key":    ks("app.zip", 4),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-726" {
		t.Fatalf("expected 1 finding for 726, got %d", len(f))
	}
}

func TestLambdaS3UnpinnedObjectQuiet(t *testing.T) {
	f := runRule(lambdaS3UnpinnedObject{},
		res("aws_lambda_function", "f", map[string]ir.Value{
			"s3_bucket":         ks("my-bucket", 3),
			"s3_key":            ks("app.zip", 4),
			"s3_object_version": ks("abc123", 5),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestLambdaS3UnpinnedObjectNoS3Quiet(t *testing.T) {
	f := runRule(lambdaS3UnpinnedObject{},
		res("aws_lambda_function", "f", map[string]ir.Value{
			"filename": ks("app.zip", 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-727
// ---------------------------------------------------------------------------

func TestEsmNoMaxRetriesFires(t *testing.T) {
	f := runRule(esmNoMaxRetries{},
		res("aws_lambda_event_source_mapping", "m", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-727" {
		t.Fatalf("expected 1 finding for 727, got %d", len(f))
	}
}

func TestEsmNoMaxRetriesQuiet(t *testing.T) {
	f := runRule(esmNoMaxRetries{},
		res("aws_lambda_event_source_mapping", "m", map[string]ir.Value{
			"maximum_retry_attempts": intVal(3, 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-728
// ---------------------------------------------------------------------------

func TestEsmNoBisectOnErrorFires(t *testing.T) {
	f := runRule(esmNoBisectOnError{},
		res("aws_lambda_event_source_mapping", "m", map[string]ir.Value{
			"bisect_batch_on_function_error": kv(false, 3),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-728" {
		t.Fatalf("expected 1 finding for 728, got %d", len(f))
	}
}

func TestEsmNoBisectOnErrorAbsentFires(t *testing.T) {
	f := runRule(esmNoBisectOnError{},
		res("aws_lambda_event_source_mapping", "m", map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestEsmNoBisectOnErrorQuiet(t *testing.T) {
	f := runRule(esmNoBisectOnError{},
		res("aws_lambda_event_source_mapping", "m", map[string]ir.Value{
			"bisect_batch_on_function_error": kv(true, 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-729
// ---------------------------------------------------------------------------

func TestSfnLoggingOffFires(t *testing.T) {
	f := runRule(sfnLoggingOff{},
		res("aws_sfn_state_machine", "s", map[string]ir.Value{
			"logging_configuration": blks(3, blk("level", ks("OFF", 4))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-729" {
		t.Fatalf("expected 1 finding for 729, got %d", len(f))
	}
}

func TestSfnLoggingOffQuiet(t *testing.T) {
	f := runRule(sfnLoggingOff{},
		res("aws_sfn_state_machine", "s", map[string]ir.Value{
			"logging_configuration": blks(3, blk("level", ks("ALL", 4))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestSfnLoggingOffAbsentQuiet(t *testing.T) {
	// Absent logging_configuration is rule 376's territory, not 729's.
	f := runRule(sfnLoggingOff{},
		res("aws_sfn_state_machine", "s", map[string]ir.Value{}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-730
// ---------------------------------------------------------------------------

func TestSfnTracingDisabledFires(t *testing.T) {
	f := runRule(sfnTracingDisabled{},
		res("aws_sfn_state_machine", "s", map[string]ir.Value{
			"tracing_configuration": blks(3, blk("enabled", kv(false, 4))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-730" {
		t.Fatalf("expected 1 finding for 730, got %d", len(f))
	}
}

func TestSfnTracingDisabledQuiet(t *testing.T) {
	f := runRule(sfnTracingDisabled{},
		res("aws_sfn_state_machine", "s", map[string]ir.Value{
			"tracing_configuration": blks(3, blk("enabled", kv(true, 4))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-731
// ---------------------------------------------------------------------------

func TestSfnHardcodedSecretsFires(t *testing.T) {
	f := runRule(sfnHardcodedSecrets{},
		res("aws_sfn_state_machine", "s", map[string]ir.Value{
			"definition": ks(`{"StartAt":"x","States":{"x":{"Type":"Pass","Parameters":{"db_password":"s3cr3t"}}}}`, 3),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-731" {
		t.Fatalf("expected 1 finding for 731, got %d", len(f))
	}
}

func TestSfnHardcodedSecretsQuiet(t *testing.T) {
	f := runRule(sfnHardcodedSecrets{},
		res("aws_sfn_state_machine", "s", map[string]ir.Value{
			"definition": ks(`{"StartAt":"x","States":{"x":{"Type":"Pass"}}}`, 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestSfnHardcodedSecretsUnknownQuiet(t *testing.T) {
	f := runRule(sfnHardcodedSecrets{},
		res("aws_sfn_state_machine", "s", map[string]ir.Value{"definition": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-732
// ---------------------------------------------------------------------------

func TestLambdaLayerNoRuntimesFires(t *testing.T) {
	f := runRule(lambdaLayerNoRuntimes{},
		res("aws_lambda_layer_version", "l", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-732" {
		t.Fatalf("expected 1 finding for 732, got %d", len(f))
	}
}

func TestLambdaLayerNoRuntimesQuiet(t *testing.T) {
	f := runRule(lambdaLayerNoRuntimes{},
		res("aws_lambda_layer_version", "l", map[string]ir.Value{
			"compatible_runtimes": strList(3, "python3.12"),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-733
// ---------------------------------------------------------------------------

func TestCodeSigningNoPublishersFires(t *testing.T) {
	f := runRule(codeSigningNoPublishers{},
		res("aws_lambda_code_signing_config", "c", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-733" {
		t.Fatalf("expected 1 finding for 733, got %d", len(f))
	}
}

func TestCodeSigningNoPublishersQuiet(t *testing.T) {
	f := runRule(codeSigningNoPublishers{},
		res("aws_lambda_code_signing_config", "c", map[string]ir.Value{
			"allowed_publishers": blks(3, blk("signing_profile_version_arns", strList(4, "arn:aws:signer:us-east-1:123456789012:/signing-profiles/test"))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-734
// ---------------------------------------------------------------------------

func TestEcsHostNamespacesFires(t *testing.T) {
	f := runRule(ecsHostNamespaces{},
		res("aws_ecs_task_definition", "t", map[string]ir.Value{"pid_mode": ks("host", 3)}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-734" {
		t.Fatalf("expected 1 finding for 734, got %d", len(f))
	}
}

func TestEcsHostNamespacesQuiet(t *testing.T) {
	f := runRule(ecsHostNamespaces{},
		res("aws_ecs_task_definition", "t", map[string]ir.Value{"pid_mode": ks("task", 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestEcsHostNamespacesUnknownQuiet(t *testing.T) {
	f := runRule(ecsHostNamespaces{},
		res("aws_ecs_task_definition", "t", map[string]ir.Value{"ipc_mode": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-735
// ---------------------------------------------------------------------------

func TestEcsContainerNoLogConfigFires(t *testing.T) {
	f := runRule(ecsContainerNoLogConfig{},
		res("aws_ecs_task_definition", "t", map[string]ir.Value{
			"container_definitions": ks(`[{"name":"app","image":"x"}]`, 3),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-735" {
		t.Fatalf("expected 1 finding for 735, got %d", len(f))
	}
}

func TestEcsContainerNoLogConfigQuiet(t *testing.T) {
	f := runRule(ecsContainerNoLogConfig{},
		res("aws_ecs_task_definition", "t", map[string]ir.Value{
			"container_definitions": ks(`[{"name":"app","logConfiguration":{"logDriver":"awslogs"}}]`, 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestEcsContainerNoLogConfigUnknownQuiet(t *testing.T) {
	f := runRule(ecsContainerNoLogConfig{},
		res("aws_ecs_task_definition", "t", map[string]ir.Value{"container_definitions": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-736
// ---------------------------------------------------------------------------

func TestEcsServiceExecEnabledFires(t *testing.T) {
	f := runRule(ecsServiceExecEnabled{},
		res("aws_ecs_service", "s", map[string]ir.Value{"enable_execute_command": kv(true, 3)}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-736" {
		t.Fatalf("expected 1 finding for 736, got %d", len(f))
	}
}

func TestEcsServiceExecEnabledQuiet(t *testing.T) {
	f := runRule(ecsServiceExecEnabled{},
		res("aws_ecs_service", "s", map[string]ir.Value{"enable_execute_command": kv(false, 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-737
// ---------------------------------------------------------------------------

func TestEcsServiceLowHealthyPercentFires(t *testing.T) {
	f := runRule(ecsServiceLowHealthyPercent{},
		res("aws_ecs_service", "s", map[string]ir.Value{"deployment_minimum_healthy_percent": intVal(50, 3)}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-737" {
		t.Fatalf("expected 1 finding for 737, got %d", len(f))
	}
}

func TestEcsServiceLowHealthyPercentQuiet(t *testing.T) {
	f := runRule(ecsServiceLowHealthyPercent{},
		res("aws_ecs_service", "s", map[string]ir.Value{"deployment_minimum_healthy_percent": intVal(100, 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestEcsServiceLowHealthyPercentUnknownQuiet(t *testing.T) {
	f := runRule(ecsServiceLowHealthyPercent{},
		res("aws_ecs_service", "s", map[string]ir.Value{"deployment_minimum_healthy_percent": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-738
// ---------------------------------------------------------------------------

func TestEksNoAuditLogFires(t *testing.T) {
	f := runRule(eksNoAuditLog{},
		res("aws_eks_cluster", "c", map[string]ir.Value{
			"enabled_cluster_log_types": strList(3, "api", "authenticator"),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-738" {
		t.Fatalf("expected 1 finding for 738, got %d", len(f))
	}
}

func TestEksNoAuditLogQuiet(t *testing.T) {
	f := runRule(eksNoAuditLog{},
		res("aws_eks_cluster", "c", map[string]ir.Value{
			"enabled_cluster_log_types": strList(3, "api", "audit"),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestEksNoAuditLogAbsentQuiet(t *testing.T) {
	// Absent list is rule 306's territory, not 738's.
	f := runRule(eksNoAuditLog{},
		res("aws_eks_cluster", "c", map[string]ir.Value{}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-739
// ---------------------------------------------------------------------------

func TestEksSecretsNotEncryptedFires(t *testing.T) {
	f := runRule(eksSecretsNotEncrypted{},
		res("aws_eks_cluster", "c", map[string]ir.Value{
			"encryption_config": blks(3, blk("resources", strList(4, "configmaps"))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-739" {
		t.Fatalf("expected 1 finding for 739, got %d", len(f))
	}
}

func TestEksSecretsNotEncryptedQuiet(t *testing.T) {
	f := runRule(eksSecretsNotEncrypted{},
		res("aws_eks_cluster", "c", map[string]ir.Value{
			"encryption_config": blks(3, blk("resources", strList(4, "secrets"))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestEksSecretsNotEncryptedAbsentQuiet(t *testing.T) {
	// Absent encryption_config is rule 304's territory, not 739's.
	f := runRule(eksSecretsNotEncrypted{},
		res("aws_eks_cluster", "c", map[string]ir.Value{}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}
