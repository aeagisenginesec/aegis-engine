package aws

import (
	"testing"

	"aegis/internal/ir"
)

func Test780_LongPeriodFires(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{
		"enable_key_rotation": kv(true, 3), "rotation_period_in_days": kn(730, 4),
	})
	fs := runRule(kmsRotationPeriodLong{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test780_AnnualQuiet(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{
		"enable_key_rotation": kv(true, 3), "rotation_period_in_days": kn(365, 4),
	})
	if fs := runRule(kmsRotationPeriodLong{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test780_RotationDisabledQuiet(t *testing.T) {
	// Rotation disabled is AEGIS-AWS-335's case, not this rule's.
	r := res("aws_kms_key", "k", map[string]ir.Value{"enable_key_rotation": kv(false, 3)})
	if fs := runRule(kmsRotationPeriodLong{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test781_ShortWindowFires(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{"deletion_window_in_days": kn(7, 3)})
	fs := runRule(kmsDeletionWindowShort{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test781_DefaultQuiet(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{"deletion_window_in_days": kn(30, 3)})
	if fs := runRule(kmsDeletionWindowShort{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test782_PublicPrincipalFires(t *testing.T) {
	doc := `{"Statement":[{"Sid":"open","Effect":"Allow","Principal":"*","Action":"kms:*","Resource":"*"}]}`
	r := res("aws_kms_key", "k", map[string]ir.Value{"policy": ks(doc, 3)})
	fs := runRule(kmsKeyPolicyPublic{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test782_ScopedPrincipalQuiet(t *testing.T) {
	doc := `{"Statement":[{"Sid":"root","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"kms:*","Resource":"*"}]}`
	r := res("aws_kms_key", "k", map[string]ir.Value{"policy": ks(doc, 3)})
	if fs := runRule(kmsKeyPolicyPublic{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test783_AbsentFires(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{})
	fs := runRule(kmsKeyNoDescription{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test783_WithDescriptionQuiet(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{"description": ks("app data key", 3)})
	if fs := runRule(kmsKeyNoDescription{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test784_AbsentFires(t *testing.T) {
	r := res("aws_kms_external_key", "k", map[string]ir.Value{})
	fs := runRule(kmsExternalKeyNoExpiry{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test784_WithValidToQuiet(t *testing.T) {
	r := res("aws_kms_external_key", "k", map[string]ir.Value{"valid_to": ks("2027-01-01T00:00:00Z", 3)})
	if fs := runRule(kmsExternalKeyNoExpiry{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test785_BypassTrueFires(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{"bypass_policy_lockout_safety_check": kv(true, 3)})
	fs := runRule(kmsBypassLockoutSafetyCheck{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test785_DefaultQuiet(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{})
	if fs := runRule(kmsBypassLockoutSafetyCheck{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test786_AWSManagedKeyFires(t *testing.T) {
	r := res("aws_ebs_default_kms_key", "d", map[string]ir.Value{"key_arn": ks("alias/aws/ebs", 3)})
	fs := runRule(ebsDefaultKMSAWSManaged{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test786_CMKQuiet(t *testing.T) {
	r := res("aws_ebs_default_kms_key", "d", map[string]ir.Value{"key_arn": ks("arn:aws:kms:us-east-1:123:key/abcd", 3)})
	if fs := runRule(ebsDefaultKMSAWSManaged{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test787_AWSManagedKeyFires(t *testing.T) {
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{"kms_key_id": ks("alias/aws/secretsmanager", 3)})
	fs := runRule(secretsManagerAWSManagedKey{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test787_CMKQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{"kms_key_id": ks("arn:aws:kms:us-east-1:123:key/abcd", 3)})
	if fs := runRule(secretsManagerAWSManagedKey{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test787_AbsentQuiet(t *testing.T) {
	// absent kms_key_id is AEGIS-AWS-563's case.
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{})
	if fs := runRule(secretsManagerAWSManagedKey{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test788_SixtyDaysFires(t *testing.T) {
	r := res("aws_secretsmanager_secret_rotation", "r", map[string]ir.Value{
		"rotation_rules": blks(4, blk("automatically_after_days", kn(60, 5))),
	})
	fs := runRule(secretsRotationAbove30Days{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test788_ThirtyDaysQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret_rotation", "r", map[string]ir.Value{
		"rotation_rules": blks(4, blk("automatically_after_days", kn(30, 5))),
	})
	if fs := runRule(secretsRotationAbove30Days{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test788_OverNinetyQuiet(t *testing.T) {
	// > 90 days is AEGIS-AWS-337's case, not this rule's.
	r := res("aws_secretsmanager_secret_rotation", "r", map[string]ir.Value{
		"rotation_rules": blks(4, blk("automatically_after_days", kn(120, 5))),
	})
	if fs := runRule(secretsRotationAbove30Days{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test789_AbsentFires(t *testing.T) {
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{})
	fs := runRule(secretsManagerNoDescription{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test789_WithDescriptionQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{"description": ks("db creds", 3)})
	if fs := runRule(secretsManagerNoDescription{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test790_DefaultKeyFires(t *testing.T) {
	r := res("aws_ssm_parameter", "p", map[string]ir.Value{
		"name": ks("/app/db_password", 3), "type": ks("SecureString", 4),
	})
	fs := runRule(ssmSecureStringDefaultKey{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test790_WithKeyQuiet(t *testing.T) {
	r := res("aws_ssm_parameter", "p", map[string]ir.Value{
		"name": ks("/app/db_password", 3), "type": ks("SecureString", 4),
		"key_id": ks("alias/app-key", 5),
	})
	if fs := runRule(ssmSecureStringDefaultKey{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test790_PlainStringQuiet(t *testing.T) {
	r := res("aws_ssm_parameter", "p", map[string]ir.Value{
		"name": ks("/app/region", 3), "type": ks("String", 4),
	})
	if fs := runRule(ssmSecureStringDefaultKey{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test791_StringListSecretFires(t *testing.T) {
	r := res("aws_ssm_parameter", "p", map[string]ir.Value{
		"name": ks("/app/api_tokens", 3), "type": ks("StringList", 4),
	})
	fs := runRule(ssmStringListPlaintextSecret{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test791_SecureStringQuiet(t *testing.T) {
	r := res("aws_ssm_parameter", "p", map[string]ir.Value{
		"name": ks("/app/api_tokens", 3), "type": ks("SecureString", 4),
	})
	if fs := runRule(ssmStringListPlaintextSecret{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test791_NonSecretNameQuiet(t *testing.T) {
	r := res("aws_ssm_parameter", "p", map[string]ir.Value{
		"name": ks("/app/regions", 3), "type": ks("StringList", 4),
	})
	if fs := runRule(ssmStringListPlaintextSecret{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test792_PublicSharingFires(t *testing.T) {
	r := res("aws_ssm_document", "d", map[string]ir.Value{
		"permissions": blks(4, blk("account_ids", strList(5, "all"))),
	})
	fs := runRule(ssmDocumentPublicSharing{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test792_SpecificAccountQuiet(t *testing.T) {
	r := res("aws_ssm_document", "d", map[string]ir.Value{
		"permissions": blks(4, blk("account_ids", strList(5, "123456789012"))),
	})
	if fs := runRule(ssmDocumentPublicSharing{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test793_PlaceholderFires(t *testing.T) {
	r := res("aws_secretsmanager_secret_version", "v", map[string]ir.Value{"secret_string": ks("changeme", 3)})
	fs := runRule(secretsManagerWeakSecret{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test793_JsonPlaceholderFires(t *testing.T) {
	r := res("aws_secretsmanager_secret_version", "v", map[string]ir.Value{
		"secret_string": ks(`{"username":"admin","password":"password123"}`, 3),
	})
	fs := runRule(secretsManagerWeakSecret{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test793_RealSecretQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret_version", "v", map[string]ir.Value{"secret_string": ks("xJ8#kL2$mN9!pQ4&wR7*", 3)})
	if fs := runRule(secretsManagerWeakSecret{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test793_UnknownQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret_version", "v", map[string]ir.Value{"secret_string": ku(3)})
	if fs := runRule(secretsManagerWeakSecret{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test794_ComboFires(t *testing.T) {
	r := res("aws_kms_grant", "g", map[string]ir.Value{
		"operations": strList(3, "Decrypt", "RetireGrant"),
	})
	fs := runRule(kmsGrantDecryptRetire{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test794_DecryptOnlyQuiet(t *testing.T) {
	r := res("aws_kms_grant", "g", map[string]ir.Value{
		"operations": strList(3, "Decrypt", "DescribeKey"),
	})
	if fs := runRule(kmsGrantDecryptRetire{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test795_PublicGranteeFires(t *testing.T) {
	r := res("aws_kms_grant", "g", map[string]ir.Value{"grantee_principal": ks("*", 3)})
	fs := runRule(kmsGrantPublicGrantee{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test795_SpecificGranteeQuiet(t *testing.T) {
	r := res("aws_kms_grant", "g", map[string]ir.Value{"grantee_principal": ks("arn:aws:iam::123:role/app", 3)})
	if fs := runRule(kmsGrantPublicGrantee{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test796_PublicPolicyFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
	r := res("aws_secretsmanager_secret_policy", "p", map[string]ir.Value{"policy": ks(doc, 3)})
	fs := runRule(secretsManagerPolicyPublic{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test796_ScopedPolicyQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/app"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
	r := res("aws_secretsmanager_secret_policy", "p", map[string]ir.Value{"policy": ks(doc, 3)})
	if fs := runRule(secretsManagerPolicyPublic{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test797_ReservedPrefixFires(t *testing.T) {
	r := res("aws_ssm_parameter", "p", map[string]ir.Value{"name": ks("/aws/service/ami-amazon-linux-latest/x", 3)})
	fs := runRule(ssmParameterReservedPrefix{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test797_NormalNameQuiet(t *testing.T) {
	r := res("aws_ssm_parameter", "p", map[string]ir.Value{"name": ks("/app/config", 3)})
	if fs := runRule(ssmParameterReservedPrefix{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test798_MissingSidFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"kms:*","Resource":"*"}]}`
	r := res("aws_kms_key", "k", map[string]ir.Value{"policy": ks(doc, 3)})
	fs := runRule(kmsKeyPolicyStatementNoSid{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test798_WithSidQuiet(t *testing.T) {
	doc := `{"Statement":[{"Sid":"EnableRoot","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"kms:*","Resource":"*"}]}`
	r := res("aws_kms_key", "k", map[string]ir.Value{"policy": ks(doc, 3)})
	if fs := runRule(kmsKeyPolicyStatementNoSid{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test799_ZeroWindowFires(t *testing.T) {
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{"recovery_window_in_days": kn(0, 3)})
	fs := runRule(secretsManagerZeroRecoveryWindow{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test799_DefaultQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{"recovery_window_in_days": kn(30, 3)})
	if fs := runRule(secretsManagerZeroRecoveryWindow{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}
