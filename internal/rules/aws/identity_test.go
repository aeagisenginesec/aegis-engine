package aws

import (
	"testing"

	"aegis/internal/ir"
)

// adminDoc builds a policy JSON string with the given effect/action/resource.
func adminDoc(effect, action, resource string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"` + effect +
		`","Action":"` + action + `","Resource":"` + resource + `"}]}`
}

// --- 333: inline admin policy ----------------------------------------------

func Test333_AdminFires(t *testing.T) {
	for _, typ := range []string{"aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"} {
		p := res(typ, "admin", map[string]ir.Value{
			"policy": ks(adminDoc("Allow", "*", "*"), 4),
		})
		f := runRule(inlineAdminPolicyRule{}, p)
		if len(f) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", typ, len(f))
		}
		if f[0].Severity != "high" {
			t.Fatalf("%s: wrong severity: %s", typ, f[0].Severity)
		}
	}
}

func Test333_StarServiceActionFires(t *testing.T) {
	p := res("aws_iam_role_policy", "admin", map[string]ir.Value{
		"policy": ks(adminDoc("Allow", "*:*", "*"), 4),
	})
	if len(runRule(inlineAdminPolicyRule{}, p)) != 1 {
		t.Fatal("expected 1 finding for Action \"*:*\"")
	}
}

func Test333_ScopedQuiet(t *testing.T) {
	p := res("aws_iam_role_policy", "ro", map[string]ir.Value{
		"policy": ks(adminDoc("Allow", "s3:GetObject", "*"), 4),
	})
	if len(runRule(inlineAdminPolicyRule{}, p)) != 0 {
		t.Fatal("scoped action must not fire")
	}
}

func Test333_DenyStarQuiet(t *testing.T) {
	p := res("aws_iam_role_policy", "deny", map[string]ir.Value{
		"policy": ks(adminDoc("Deny", "*", "*"), 4),
	})
	if len(runRule(inlineAdminPolicyRule{}, p)) != 0 {
		t.Fatal("Deny effect must not fire")
	}
}

func Test333_BadJSONQuiet(t *testing.T) {
	p := res("aws_iam_role_policy", "broken", map[string]ir.Value{
		"policy": ks("{not json", 4),
	})
	if len(runRule(inlineAdminPolicyRule{}, p)) != 0 {
		t.Fatal("unparseable policy must not fire")
	}
}

func Test333_UnknownQuiet(t *testing.T) {
	p := res("aws_iam_role_policy", "x", map[string]ir.Value{"policy": ku(4)})
	if len(runRule(inlineAdminPolicyRule{}, p)) != 0 {
		t.Fatal("unknown policy must not fire")
	}
}

// --- 334: password policy ---------------------------------------------------

func Test334_ShortLengthFires(t *testing.T) {
	p := res("aws_iam_account_password_policy", "strict", map[string]ir.Value{
		"minimum_password_length": {Raw: float64(8), Known: true, Span: spanAt(2)},
	})
	f := runRule(weakPasswordPolicy{}, p)
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(f))
	}
	if f[0].Severity != "medium" {
		t.Fatalf("wrong severity: %s", f[0].Severity)
	}
}

func Test334_MultipleWeaknessesOneFinding(t *testing.T) {
	p := res("aws_iam_account_password_policy", "weak", map[string]ir.Value{
		"minimum_password_length":   {Raw: float64(8), Known: true, Span: spanAt(2)},
		"require_symbols":           kv(false, 3),
		"password_reuse_prevention": {Raw: float64(0), Known: true, Span: spanAt(4)},
	})
	if len(runRule(weakPasswordPolicy{}, p)) != 1 {
		t.Fatal("multiple weaknesses must yield exactly one finding")
	}
}

func Test334_StrongQuiet(t *testing.T) {
	p := res("aws_iam_account_password_policy", "strict", map[string]ir.Value{
		"minimum_password_length":      {Raw: float64(16), Known: true, Span: spanAt(2)},
		"require_lowercase_characters": kv(true, 3),
		"require_uppercase_characters": kv(true, 4),
		"require_numbers":              kv(true, 5),
		"require_symbols":              kv(true, 6),
		"password_reuse_prevention":    {Raw: float64(5), Known: true, Span: spanAt(7)},
	})
	if len(runRule(weakPasswordPolicy{}, p)) != 0 {
		t.Fatal("strong policy must not fire")
	}
}

func Test334_UnknownLengthQuiet(t *testing.T) {
	// Isolate the unknown-length case: everything else strong, so an
	// unknown length alone must not fire.
	p := res("aws_iam_account_password_policy", "x", map[string]ir.Value{
		"minimum_password_length":      ku(2),
		"require_lowercase_characters": kv(true, 3),
		"require_uppercase_characters": kv(true, 4),
		"require_numbers":              kv(true, 5),
		"require_symbols":              kv(true, 6),
		"password_reuse_prevention":    {Raw: float64(5), Known: true, Span: spanAt(7)},
	})
	if len(runRule(weakPasswordPolicy{}, p)) != 0 {
		t.Fatal("unknown length must not fire")
	}
}

// --- 335: KMS rotation ------------------------------------------------------

func Test335_AbsentFires(t *testing.T) {
	k := res("aws_kms_key", "main", map[string]ir.Value{})
	f := runRule(kmsNoRotation{}, k)
	if len(f) != 1 || f[0].Severity != "high" {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
}

func Test335_FalseFires(t *testing.T) {
	k := res("aws_kms_key", "main", map[string]ir.Value{"enable_key_rotation": kv(false, 2)})
	if len(runRule(kmsNoRotation{}, k)) != 1 {
		t.Fatal("expected 1 finding")
	}
}

func Test335_TrueQuiet(t *testing.T) {
	k := res("aws_kms_key", "main", map[string]ir.Value{"enable_key_rotation": kv(true, 2)})
	if len(runRule(kmsNoRotation{}, k)) != 0 {
		t.Fatal("rotation enabled must not fire")
	}
}

func Test335_UnknownQuiet(t *testing.T) {
	k := res("aws_kms_key", "main", map[string]ir.Value{"enable_key_rotation": ku(2)})
	if len(runRule(kmsNoRotation{}, k)) != 0 {
		t.Fatal("unknown must not fire")
	}
}

// --- 336: CloudTrail multi-region -------------------------------------------

func Test336_AbsentFires(t *testing.T) {
	ct := res("aws_cloudtrail", "main", map[string]ir.Value{})
	f := runRule(cloudtrailNotMultiRegion{}, ct)
	if len(f) != 1 || f[0].Severity != "high" {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
}

func Test336_TrueQuiet(t *testing.T) {
	ct := res("aws_cloudtrail", "main", map[string]ir.Value{"is_multi_region_trail": kv(true, 2)})
	if len(runRule(cloudtrailNotMultiRegion{}, ct)) != 0 {
		t.Fatal("multi-region trail must not fire")
	}
}

func Test336_UnknownQuiet(t *testing.T) {
	ct := res("aws_cloudtrail", "main", map[string]ir.Value{"is_multi_region_trail": ku(2)})
	if len(runRule(cloudtrailNotMultiRegion{}, ct)) != 0 {
		t.Fatal("unknown must not fire")
	}
}

// --- 337: rotation interval --------------------------------------------------

func Test337_LongIntervalFires(t *testing.T) {
	r := res("aws_secretsmanager_secret_rotation", "db", map[string]ir.Value{
		"rotation_rules": blks(3, blk("automatically_after_days",
			ir.Value{Raw: float64(180), Known: true, Span: spanAt(4)})),
	})
	f := runRule(secretsRotationInterval{}, r)
	if len(f) != 1 || f[0].Severity != "medium" {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
}

func Test337_ShortIntervalQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret_rotation", "db", map[string]ir.Value{
		"rotation_rules": blks(3, blk("automatically_after_days",
			ir.Value{Raw: float64(30), Known: true, Span: spanAt(4)})),
	})
	if len(runRule(secretsRotationInterval{}, r)) != 0 {
		t.Fatal("30-day interval must not fire")
	}
}

func Test337_NoRulesQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret_rotation", "db", map[string]ir.Value{})
	if len(runRule(secretsRotationInterval{}, r)) != 0 {
		t.Fatal("absent rotation_rules must not fire")
	}
}

func Test337_UnknownIntervalQuiet(t *testing.T) {
	r := res("aws_secretsmanager_secret_rotation", "db", map[string]ir.Value{
		"rotation_rules": blks(3, blk("automatically_after_days", ku(4))),
	})
	if len(runRule(secretsRotationInterval{}, r)) != 0 {
		t.Fatal("unknown interval must not fire")
	}
}

// --- 338: SSM plaintext secret -----------------------------------------------

func Test338_PlaintextSecretNameFires(t *testing.T) {
	for _, name := range []string{"db_password", "API_SECRET", "auth-token"} {
		p := res("aws_ssm_parameter", "s", map[string]ir.Value{
			"type":  ks("String", 2),
			"name":  ks(name, 3),
			"value": ks("hunter2", 4),
		})
		f := runRule(ssmPlaintextSecret{}, p)
		if len(f) != 1 {
			t.Fatalf("name=%q: expected 1 finding, got %d", name, len(f))
		}
		if f[0].Evidence.Actual == "hunter2" {
			t.Fatalf("name=%q: secret value leaked into evidence", name)
		}
	}
}

func Test338_SecureStringQuiet(t *testing.T) {
	p := res("aws_ssm_parameter", "s", map[string]ir.Value{
		"type": ks("SecureString", 2),
		"name": ks("db_password", 3),
	})
	if len(runRule(ssmPlaintextSecret{}, p)) != 0 {
		t.Fatal("SecureString must not fire")
	}
}

func Test338_NonSecretNameQuiet(t *testing.T) {
	p := res("aws_ssm_parameter", "s", map[string]ir.Value{
		"type": ks("String", 2),
		"name": ks("app_config_json", 3),
	})
	if len(runRule(ssmPlaintextSecret{}, p)) != 0 {
		t.Fatal("non-secret name must not fire")
	}
}

func Test338_UnknownTypeQuiet(t *testing.T) {
	p := res("aws_ssm_parameter", "s", map[string]ir.Value{
		"type": ku(2),
		"name": ks("db_password", 3),
	})
	if len(runRule(ssmPlaintextSecret{}, p)) != 0 {
		t.Fatal("unknown type must not fire")
	}
}

// --- 339: hardcoded credentials ------------------------------------------------

func Test339_LiteralPasswordFires(t *testing.T) {
	for _, tc := range []struct {
		typ  string
		attr string
	}{
		{"aws_db_instance", "password"},
		{"aws_rds_cluster", "password"},
		{"aws_redshift_cluster", "master_password"},
		{"aws_docdb_cluster", "password"},
		{"aws_neptune_cluster", "password"},
		{"aws_fsx_ontap_file_system", "fsx_admin_password"},
	} {
		r := res(tc.typ, "main", map[string]ir.Value{
			tc.attr: ks("Sup3rSecret!", 2),
		})
		f := runRule(hardcodedCredentials{}, r)
		if len(f) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", tc.typ, len(f))
		}
		if f[0].Evidence.Actual != "[REDACTED]" {
			t.Fatalf("%s: secret value leaked: %q", tc.typ, f[0].Evidence.Actual)
		}
	}
}

func Test339_NoPasswordQuiet(t *testing.T) {
	r := res("aws_db_instance", "main", map[string]ir.Value{})
	if len(runRule(hardcodedCredentials{}, r)) != 0 {
		t.Fatal("absent password must not fire")
	}
}

func Test339_UnknownQuiet(t *testing.T) {
	r := res("aws_db_instance", "main", map[string]ir.Value{"password": ku(2)})
	if len(runRule(hardcodedCredentials{}, r)) != 0 {
		t.Fatal("unknown password must not fire")
	}
}

// --- 340: global service events -------------------------------------------------

func Test340_FalseFires(t *testing.T) {
	ct := res("aws_cloudtrail", "main", map[string]ir.Value{
		"include_global_service_events": kv(false, 2),
	})
	f := runRule(cloudtrailNoGlobalEvents{}, ct)
	if len(f) != 1 || f[0].Severity != "medium" {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
}

func Test340_TrueQuiet(t *testing.T) {
	ct := res("aws_cloudtrail", "main", map[string]ir.Value{
		"include_global_service_events": kv(true, 2),
	})
	if len(runRule(cloudtrailNoGlobalEvents{}, ct)) != 0 {
		t.Fatal("enabled must not fire")
	}
}

func Test340_AbsentQuiet(t *testing.T) {
	// Provider default is true: absent is the secure default.
	ct := res("aws_cloudtrail", "main", map[string]ir.Value{})
	if len(runRule(cloudtrailNoGlobalEvents{}, ct)) != 0 {
		t.Fatal("absent must not fire (default is true)")
	}
}

func Test340_UnknownQuiet(t *testing.T) {
	ct := res("aws_cloudtrail", "main", map[string]ir.Value{
		"include_global_service_events": ku(2),
	})
	if len(runRule(cloudtrailNoGlobalEvents{}, ct)) != 0 {
		t.Fatal("unknown must not fire")
	}
}

// --- IdentityRules ordering ----------------------------------------------------

func TestIdentityRules_OrderAndIDs(t *testing.T) {
	rules := IdentityRules()
	want := []string{
		"AEGIS-AWS-333", "AEGIS-AWS-334", "AEGIS-AWS-335", "AEGIS-AWS-336",
		"AEGIS-AWS-337", "AEGIS-AWS-338", "AEGIS-AWS-339", "AEGIS-AWS-340",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, id := range want {
		if rules[i].ID() != id {
			t.Fatalf("rule %d: expected %s, got %s", i, id, rules[i].ID())
		}
	}
}
