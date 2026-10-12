package aws

// Rule IDs covered in this file: AEGIS-AWS-421, AEGIS-AWS-422, AEGIS-AWS-424, AEGIS-AWS-425, AEGIS-AWS-426, AEGIS-AWS-428

import (
	"fmt"
	"testing"

	"aegis/internal/ir"
)

func TestIdentity2RulesIDOrder(t *testing.T) {
	rules := Identity2Rules()
	for i, r := range rules {
		want := fmt.Sprintf("AEGIS-AWS-%d", 421+i)
		if r.ID() != want {
			t.Fatalf("rule %d: want ID %s, got %s", i, want, r.ID())
		}
	}
}

// --- 421: Cognito identity pool unauthenticated ---

func Test421_Fires(t *testing.T) {
	r := res("aws_cognito_identity_pool", "p", map[string]ir.Value{
		"allow_unauthenticated_identities": kv(true, 3),
	})
	fs := runRule(cognitoIdentityUnauth{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high severity, got %s", fs[0].Severity)
	}
}

func Test421_DisabledQuiet(t *testing.T) {
	r := res("aws_cognito_identity_pool", "p", map[string]ir.Value{
		"allow_unauthenticated_identities": kv(false, 3),
	})
	if fs := runRule(cognitoIdentityUnauth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test421_UnknownQuiet(t *testing.T) {
	r := res("aws_cognito_identity_pool", "p", map[string]ir.Value{
		"allow_unauthenticated_identities": ku(3),
	})
	if fs := runRule(cognitoIdentityUnauth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 422: SSO permission set inline admin policy ---

func Test422_Fires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	r := res("aws_ssoadmin_permission_set_inline_policy", "p", map[string]ir.Value{
		"inline_policy": ks(doc, 3),
	})
	fs := runRule(ssoAdminInlinePolicy{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test422_ScopedQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`
	r := res("aws_ssoadmin_permission_set_inline_policy", "p", map[string]ir.Value{
		"inline_policy": ks(doc, 3),
	})
	if fs := runRule(ssoAdminInlinePolicy{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test422_UnknownQuiet(t *testing.T) {
	r := res("aws_ssoadmin_permission_set_inline_policy", "p", map[string]ir.Value{
		"inline_policy": ku(3),
	})
	if fs := runRule(ssoAdminInlinePolicy{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 423: Organization without SCPs ---

func Test423_Fires(t *testing.T) {
	r := res("aws_organizations_organization", "o", map[string]ir.Value{
		"enabled_policy_types": strList(3, "AISERVICES_OPT_OUT_POLICY"),
	})
	fs := runRule(orgNoSCPs{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test423_SCPEnabledQuiet(t *testing.T) {
	r := res("aws_organizations_organization", "o", map[string]ir.Value{
		"enabled_policy_types": strList(3, "SERVICE_CONTROL_POLICY"),
	})
	if fs := runRule(orgNoSCPs{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test423_AbsentQuiet(t *testing.T) {
	r := res("aws_organizations_organization", "o", map[string]ir.Value{})
	if fs := runRule(orgNoSCPs{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test423_UnknownElementQuiet(t *testing.T) {
	r := res("aws_organizations_organization", "o", map[string]ir.Value{
		"enabled_policy_types": {Raw: []ir.Value{ku(3)}, Known: true, Span: spanAt(3)},
	})
	if fs := runRule(orgNoSCPs{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 424: WorkSpaces volumes unencrypted ---

func Test424_RootUnencryptedFires(t *testing.T) {
	r := res("aws_workspaces_workspace", "w", map[string]ir.Value{
		"root_volume_encryption_enabled": kv(false, 3),
		"user_volume_encryption_enabled": kv(true, 4),
	})
	fs := runRule(workspacesUnencrypted{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test424_BothEncryptedQuiet(t *testing.T) {
	r := res("aws_workspaces_workspace", "w", map[string]ir.Value{
		"root_volume_encryption_enabled": kv(true, 3),
		"user_volume_encryption_enabled": kv(true, 4),
	})
	if fs := runRule(workspacesUnencrypted{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test424_UnknownQuiet(t *testing.T) {
	r := res("aws_workspaces_workspace", "w", map[string]ir.Value{
		"root_volume_encryption_enabled": ku(3),
	})
	if fs := runRule(workspacesUnencrypted{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 425: Secrets Manager version hardcoded secret ---

func Test425_Fires(t *testing.T) {
	r := res("aws_secretsmanager_secret_version", "v", map[string]ir.Value{
		"secret_string": ks(`{"user":"admin","pass":"s3cret"}`, 3),
	})
	fs := runRule(secretsVersionHardcoded{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Evidence.Actual != "[REDACTED]" {
		t.Fatalf("secret must be redacted, got %q", fs[0].Evidence.Actual)
	}
}

func Test425_AbsentQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret_version", "v", map[string]ir.Value{})
	if fs := runRule(secretsVersionHardcoded{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test425_UnknownQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret_version", "v", map[string]ir.Value{
		"secret_string": ku(3),
	})
	if fs := runRule(secretsVersionHardcoded{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 426: SNS subscription plaintext HTTP ---

func Test426_Fires(t *testing.T) {
	r := res("aws_sns_topic_subscription", "s", map[string]ir.Value{
		"protocol": ks("http", 3),
	})
	fs := runRule(snsSubscriptionHTTP{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test426_HTTPSQuiet(t *testing.T) {
	r := res("aws_sns_topic_subscription", "s", map[string]ir.Value{
		"protocol": ks("https", 3),
	})
	if fs := runRule(snsSubscriptionHTTP{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test426_UnknownQuiet(t *testing.T) {
	r := res("aws_sns_topic_subscription", "s", map[string]ir.Value{
		"protocol": ku(3),
	})
	if fs := runRule(snsSubscriptionHTTP{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 427: SageMaker notebook direct internet ---

func Test427_Fires(t *testing.T) {
	r := res("aws_sagemaker_notebook_instance", "n", map[string]ir.Value{
		"direct_internet_access": ks("Enabled", 3),
	})
	fs := runRule(sagemakerDirectInternet{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium severity, got %s", fs[0].Severity)
	}
}

func Test427_DisabledQuiet(t *testing.T) {
	r := res("aws_sagemaker_notebook_instance", "n", map[string]ir.Value{
		"direct_internet_access": ks("Disabled", 3),
	})
	if fs := runRule(sagemakerDirectInternet{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test427_UnknownQuiet(t *testing.T) {
	r := res("aws_sagemaker_notebook_instance", "n", map[string]ir.Value{
		"direct_internet_access": ku(3),
	})
	if fs := runRule(sagemakerDirectInternet{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 428: ElastiCache user open access ---

func Test428_Fires(t *testing.T) {
	r := res("aws_elasticache_user", "u", map[string]ir.Value{
		"access_string": ks("on ~* +@all", 3),
	})
	fs := runRule(elasticacheOpenUser{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test428_ScopedQuiet(t *testing.T) {
	r := res("aws_elasticache_user", "u", map[string]ir.Value{
		"access_string": ks("on ~app::* +@read +@write", 3),
	})
	if fs := runRule(elasticacheOpenUser{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test428_PartialSignalsQuiet(t *testing.T) {
	// Only one of the two signals: not open access.
	r := res("aws_elasticache_user", "u", map[string]ir.Value{
		"access_string": ks("on ~* +@read", 3),
	})
	if fs := runRule(elasticacheOpenUser{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test428_UnknownQuiet(t *testing.T) {
	r := res("aws_elasticache_user", "u", map[string]ir.Value{
		"access_string": ku(3),
	})
	if fs := runRule(elasticacheOpenUser{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 429: Neptune without backup retention ---

func Test429_ZeroFires(t *testing.T) {
	r := res("aws_neptune_cluster", "c", map[string]ir.Value{
		"backup_retention_period": kn(0, 3),
	})
	fs := runRule(neptuneNoBackup{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test429_AbsentFires(t *testing.T) {
	r := res("aws_neptune_cluster", "c", map[string]ir.Value{})
	if fs := runRule(neptuneNoBackup{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test429_RetainedQuiet(t *testing.T) {
	r := res("aws_neptune_cluster", "c", map[string]ir.Value{
		"backup_retention_period": kn(7, 3),
	})
	if fs := runRule(neptuneNoBackup{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test429_UnknownQuiet(t *testing.T) {
	r := res("aws_neptune_cluster", "c", map[string]ir.Value{
		"backup_retention_period": ku(3),
	})
	if fs := runRule(neptuneNoBackup{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 430: DocumentDB without deletion protection ---

func Test430_Fires(t *testing.T) {
	r := res("aws_docdb_cluster", "c", map[string]ir.Value{
		"deletion_protection": kv(false, 3),
	})
	fs := runRule(docdbNoDeletionProtection{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test430_AbsentFires(t *testing.T) {
	r := res("aws_docdb_cluster", "c", map[string]ir.Value{})
	if fs := runRule(docdbNoDeletionProtection{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test430_ProtectedQuiet(t *testing.T) {
	r := res("aws_docdb_cluster", "c", map[string]ir.Value{
		"deletion_protection": kv(true, 3),
	})
	if fs := runRule(docdbNoDeletionProtection{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test430_UnknownQuiet(t *testing.T) {
	r := res("aws_docdb_cluster", "c", map[string]ir.Value{
		"deletion_protection": ku(3),
	})
	if fs := runRule(docdbNoDeletionProtection{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test427_AbsentFires(t *testing.T) {
	// Absent direct_internet_access: the AWS API default is Enabled.
	r := res("aws_sagemaker_notebook_instance", "nb", map[string]ir.Value{})
	if fs := runRule(sagemakerDirectInternet{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}
