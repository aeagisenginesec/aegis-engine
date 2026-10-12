package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// 521: ECR image tags not immutable
// ---------------------------------------------------------------------------

func Test521_MutableFires(t *testing.T) {
	f := runRule(ecrMutableTags{}, res("aws_ecr_repository", "main",
		map[string]ir.Value{"image_tag_mutability": ks("MUTABLE", 3)}))
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("want 1 medium finding, got %+v", f)
	}
}

func Test521_AbsentFires(t *testing.T) {
	f := runRule(ecrMutableTags{}, res("aws_ecr_repository", "main",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test521_ImmutableQuiet(t *testing.T) {
	f := runRule(ecrMutableTags{}, res("aws_ecr_repository", "main",
		map[string]ir.Value{"image_tag_mutability": ks("IMMUTABLE", 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test521_UnknownQuiet(t *testing.T) {
	f := runRule(ecrMutableTags{}, res("aws_ecr_repository", "main",
		map[string]ir.Value{"image_tag_mutability": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 522: Neptune without IAM database authentication
// ---------------------------------------------------------------------------

func Test522_FalseFires(t *testing.T) {
	f := runRule(neptuneNoIAMAuth{}, res("aws_neptune_cluster", "main",
		map[string]ir.Value{"iam_database_authentication_enabled": kv(false, 3)}))
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("want 1 medium finding, got %+v", f)
	}
}

func Test522_AbsentFires(t *testing.T) {
	f := runRule(neptuneNoIAMAuth{}, res("aws_neptune_cluster", "main",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test522_EnabledQuiet(t *testing.T) {
	f := runRule(neptuneNoIAMAuth{}, res("aws_neptune_cluster", "main",
		map[string]ir.Value{"iam_database_authentication_enabled": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test522_UnknownQuiet(t *testing.T) {
	f := runRule(neptuneNoIAMAuth{}, res("aws_neptune_cluster", "main",
		map[string]ir.Value{"iam_database_authentication_enabled": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 523: OpenSearch without fine-grained access control
// ---------------------------------------------------------------------------

func Test523_AbsentBlockFires(t *testing.T) {
	f := runRule(opensearchNoFGAC{}, res("aws_opensearch_domain", "main",
		map[string]ir.Value{}))
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("want 1 medium finding, got %+v", f)
	}
}

func Test523_DisabledFires(t *testing.T) {
	f := runRule(opensearchNoFGAC{}, res("aws_opensearch_domain", "main",
		map[string]ir.Value{
			"advanced_security_options": blks(3, blk("enabled", kv(false, 4))),
		}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test523_EnabledQuiet(t *testing.T) {
	f := runRule(opensearchNoFGAC{}, res("aws_opensearch_domain", "main",
		map[string]ir.Value{
			"advanced_security_options": blks(3, blk("enabled", kv(true, 4))),
		}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test523_UnknownQuiet(t *testing.T) {
	f := runRule(opensearchNoFGAC{}, res("aws_opensearch_domain", "main",
		map[string]ir.Value{
			"advanced_security_options": blks(3, blk("enabled", ku(4))),
		}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 524: Redshift default master username
// ---------------------------------------------------------------------------

func Test524_DefaultUserFires(t *testing.T) {
	f := runRule(redshiftDefaultMasterUser{}, res("aws_redshift_cluster", "main",
		map[string]ir.Value{"master_username": ks("awsuser", 3)}))
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("want 1 medium finding, got %+v", f)
	}
}

func Test524_CustomUserQuiet(t *testing.T) {
	f := runRule(redshiftDefaultMasterUser{}, res("aws_redshift_cluster", "main",
		map[string]ir.Value{"master_username": ks("analytics_admin", 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test524_AbsentQuiet(t *testing.T) {
	f := runRule(redshiftDefaultMasterUser{}, res("aws_redshift_cluster", "main",
		map[string]ir.Value{}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test524_UnknownQuiet(t *testing.T) {
	f := runRule(redshiftDefaultMasterUser{}, res("aws_redshift_cluster", "main",
		map[string]ir.Value{"master_username": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 525: SageMaker domain without explicit auth mode
// ---------------------------------------------------------------------------

func Test525_AbsentFires(t *testing.T) {
	f := runRule(sagemakerNoAuthMode{}, res("aws_sagemaker_domain", "main",
		map[string]ir.Value{}))
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("want 1 medium finding, got %+v", f)
	}
}

func Test525_ExplicitQuiet(t *testing.T) {
	f := runRule(sagemakerNoAuthMode{}, res("aws_sagemaker_domain", "main",
		map[string]ir.Value{"auth_mode": ks("SSO", 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test525_UnknownQuiet(t *testing.T) {
	f := runRule(sagemakerNoAuthMode{}, res("aws_sagemaker_domain", "main",
		map[string]ir.Value{"auth_mode": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 526: IAM policy grants sagemaker:* on *
// ---------------------------------------------------------------------------

const sagemakerStarDoc = `{"Statement": [{"Effect": "Allow", "Action": "sagemaker:*", "Resource": "*"}]}`
const sagemakerScopedDoc = `{"Statement": [{"Effect": "Allow", "Action": "sagemaker:CreateTrainingJob", "Resource": "arn:aws:sagemaker:us-east-1:123456789012:training-job/*"}]}`
const sagemakerStarDeniedDoc = `{"Statement": [{"Effect": "Deny", "Action": "sagemaker:*", "Resource": "*"}]}`

func Test526_StarOnStarFires(t *testing.T) {
	f := runRule(sagemakerPermissivePolicy{}, res("aws_iam_policy", "main",
		map[string]ir.Value{"policy": ks(sagemakerStarDoc, 3)}))
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("want 1 medium finding, got %+v", f)
	}
}

func Test526_RolePolicyFires(t *testing.T) {
	f := runRule(sagemakerPermissivePolicy{}, res("aws_iam_role_policy", "main",
		map[string]ir.Value{"policy": ks(sagemakerStarDoc, 3)}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test526_ScopedQuiet(t *testing.T) {
	f := runRule(sagemakerPermissivePolicy{}, res("aws_iam_policy", "main",
		map[string]ir.Value{"policy": ks(sagemakerScopedDoc, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test526_DenyQuiet(t *testing.T) {
	f := runRule(sagemakerPermissivePolicy{}, res("aws_iam_policy", "main",
		map[string]ir.Value{"policy": ks(sagemakerStarDeniedDoc, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test526_UnknownQuiet(t *testing.T) {
	f := runRule(sagemakerPermissivePolicy{}, res("aws_iam_policy", "main",
		map[string]ir.Value{"policy": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test526_UnparseableQuiet(t *testing.T) {
	f := runRule(sagemakerPermissivePolicy{}, res("aws_iam_policy", "main",
		map[string]ir.Value{"policy": ks("not json", 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 527: ECS container without read-only root filesystem
// ---------------------------------------------------------------------------

const ecsWritableRootfs = `[{"name": "app", "image": "app:1", "readonlyRootFilesystem": false}]`
const ecsNoRootfsAttr = `[{"name": "app", "image": "app:1"}]`
const ecsReadonlyRootfs = `[{"name": "app", "image": "app:1", "readonlyRootFilesystem": true}]`
const ecsMixedRootfs = `[{"name": "good", "image": "g:1", "readonlyRootFilesystem": true}, {"name": "bad", "image": "b:1"}]`

func Test527_WritableFires(t *testing.T) {
	f := runRule(ecsNoReadonlyRootfs{}, res("aws_ecs_task_definition", "main",
		map[string]ir.Value{"container_definitions": ks(ecsWritableRootfs, 3)}))
	if len(f) != 1 || f[0].Severity != ir.SeverityMedium {
		t.Fatalf("want 1 medium finding, got %+v", f)
	}
}

func Test527_AbsentAttrFires(t *testing.T) {
	f := runRule(ecsNoReadonlyRootfs{}, res("aws_ecs_task_definition", "main",
		map[string]ir.Value{"container_definitions": ks(ecsNoRootfsAttr, 3)}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test527_MixedFiresOnce(t *testing.T) {
	f := runRule(ecsNoReadonlyRootfs{}, res("aws_ecs_task_definition", "main",
		map[string]ir.Value{"container_definitions": ks(ecsMixedRootfs, 3)}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding (bad container only), got %d", len(f))
	}
}

func Test527_ReadonlyQuiet(t *testing.T) {
	f := runRule(ecsNoReadonlyRootfs{}, res("aws_ecs_task_definition", "main",
		map[string]ir.Value{"container_definitions": ks(ecsReadonlyRootfs, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test527_UnknownQuiet(t *testing.T) {
	f := runRule(ecsNoReadonlyRootfs{}, res("aws_ecs_task_definition", "main",
		map[string]ir.Value{"container_definitions": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test527_UnparseableQuiet(t *testing.T) {
	f := runRule(ecsNoReadonlyRootfs{}, res("aws_ecs_task_definition", "main",
		map[string]ir.Value{"container_definitions": ks("not json", 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}
