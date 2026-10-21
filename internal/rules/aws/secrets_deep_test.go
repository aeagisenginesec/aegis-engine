package aws

import (
	"encoding/base64"
	"strings"
	"testing"

	"aegis/internal/ir"
)

// testRes builds a minimal resource for deep-secret tests.
func dsRes(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type:       typ,
		Name:       name,
		Provider:   "aws",
		Attributes: attrs,
	}
}

func dsStrVal(s string) ir.Value {
	return ir.Value{Raw: s, Known: true}
}

func dsBoolVal(b bool) ir.Value {
	return ir.Value{Raw: b, Known: true}
}

func dsMapVal(m map[string]ir.Value) ir.Value {
	return ir.Value{Raw: m, Known: true}
}

func dsListVal(l []ir.Value) ir.Value {
	return ir.Value{Raw: l, Known: true}
}

// noSecretLeak fails if any finding contains the raw secret text.
func noSecretLeak(t *testing.T, findings []ir.Finding, secrets ...string) {
	t.Helper()
	for _, f := range findings {
		blob := f.Evidence.Actual + " " + f.Evidence.Expected + " " + f.Title
		for _, s := range secrets {
			if s != "" && strings.Contains(blob, s) {
				t.Errorf("finding leaks secret %q: %v", s, f)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 534: user_data secrets
// ---------------------------------------------------------------------------

func Test534_UserDataAWSKey(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"user_data": dsStrVal("#!/bin/bash\nexport AWS_ACCESS_KEY_ID=" + secret),
	})
	f := (userDataSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	noSecretLeak(t, f, secret)
}

func Test534_UserDataBase64(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	raw := "password=hunter2super " + secret
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	r := dsRes("aws_launch_template", "lt", map[string]ir.Value{
		"user_data_base64": dsStrVal(enc),
	})
	f := (userDataSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	noSecretLeak(t, f, secret, "hunter2super")
}

func Test534_UserDataClean(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"user_data": dsStrVal("#!/bin/bash\necho hello"),
	})
	if f := (userDataSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

func Test534_UserDataAbsent(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{})
	if f := (userDataSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

func Test534_WrongType(t *testing.T) {
	if (userDataSecret{}).AppliesTo("aws_s3_bucket") {
		t.Error("534 should not apply to aws_s3_bucket")
	}
}

// Test534_UserDataSecretVarInterpolation: the multi-cloud fixture case —
// user_data writes ${var.database_password} to a world-readable file.
// The adapter cannot resolve the interpolation, but the preserved
// template still proves the exposure. Taint finding, High (like 339).
func Test534_UserDataSecretVarInterpolation(t *testing.T) {
	tmpl := "#!/bin/bash\necho \"deployment password: ${var.database_password}\" > /tmp/deploy-creds.txt\nchmod 644 /tmp/deploy-creds.txt"
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"user_data": {Known: false, Template: tmpl},
	})
	f := (userDataSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != ir.SeverityHigh {
		t.Fatalf("taint finding must be High, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Evidence.Actual, "var.database_password") {
		t.Fatalf("evidence must cite the taint ref, got %q", f[0].Evidence.Actual)
	}
}

// Test534_UserDataLocalInterpolation: ${local.<secret-like>} is taint too.
func Test534_UserDataLocalInterpolation(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"user_data": {Known: false, Template: "export DB_PASS=${local.db_password}"},
	})
	if f := (userDataSecret{}).Check(r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

// Test534_UserDataCleanVarInterpolation: a non-secret interpolation
// (${var.ami_id}) is not evidence of a secret.
func Test534_UserDataCleanVarInterpolation(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"user_data": {Known: false, Template: "echo ${var.ami_id} ${var.region}"},
	})
	if f := (userDataSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

// Test534_UserDataLiteralSecretInTemplate: a literal secret in the static
// parts of an interpolated template is a Critical literal finding.
func Test534_UserDataLiteralSecretInTemplate(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"user_data": {Known: false, Template: "password=hunter2super ${var.ami_id}"},
	})
	f := (userDataSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != ir.SeverityCritical {
		t.Fatalf("literal secret in template must be Critical, got %s", f[0].Severity)
	}
	noSecretLeak(t, f, "hunter2super")
}

// Test534_UserDataOpaqueInterpolationQuiet: a complex interpolation
// (${upper(var.x)}) is opaque — neither a literal secret nor a bare
// secret-like reference — so it stays quiet.
func Test534_UserDataOpaqueInterpolationQuiet(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"user_data": {Known: false, Template: "echo ${upper(var.x)}"},
	})
	if f := (userDataSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 535: provisioner connection password
// ---------------------------------------------------------------------------

func Test535_ProvisionerPassword(t *testing.T) {
	secret := "s3cr3t-pw-123"
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"provisioner": dsListVal([]ir.Value{
			dsMapVal(map[string]ir.Value{
				"connection": dsListVal([]ir.Value{
					dsMapVal(map[string]ir.Value{
						"password": dsStrVal(secret),
					}),
				}),
			}),
		}),
	})
	f := (provisionerSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	noSecretLeak(t, f, secret)
}

func Test535_NoProvisioner(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{})
	if f := (provisionerSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

func Test535_ProvisionerNoPassword(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"provisioner": dsListVal([]ir.Value{
			dsMapVal(map[string]ir.Value{
				"connection": dsListVal([]ir.Value{
					dsMapVal(map[string]ir.Value{
						"type": dsStrVal("ssh"),
					}),
				}),
			}),
		}),
	})
	if f := (provisionerSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 536: output secrets
// ---------------------------------------------------------------------------

func Test536_OutputSecretNoSensitive(t *testing.T) {
	r := dsRes("terraform_output", "db_password", map[string]ir.Value{
		"value": dsStrVal("placeholder"),
	})
	f := (outputSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test536_OutputMarkedSensitive(t *testing.T) {
	r := dsRes("terraform_output", "db_password", map[string]ir.Value{
		"value":     dsStrVal("placeholder"),
		"sensitive": dsBoolVal(true),
	})
	if f := (outputSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

func Test536_OutputCleanName(t *testing.T) {
	r := dsRes("terraform_output", "vpc_id", map[string]ir.Value{
		"value": dsStrVal("vpc-123"),
	})
	if f := (outputSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 537: tag secrets
// ---------------------------------------------------------------------------

func Test537_TagSecret(t *testing.T) {
	secret := "my-db-pass-123"
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"tags": dsMapVal(map[string]ir.Value{
			"Name":        dsStrVal("web"),
			"db_password": dsStrVal(secret),
		}),
	})
	f := (tagSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	noSecretLeak(t, f, secret)
}

func Test537_TagClean(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"tags": dsMapVal(map[string]ir.Value{
			"Name": dsStrVal("web"),
			"Env":  dsStrVal("prod"),
		}),
	})
	if f := (tagSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

func Test537_TagEmptyValue(t *testing.T) {
	r := dsRes("aws_instance", "web", map[string]ir.Value{
		"tags": dsMapVal(map[string]ir.Value{"api_token": dsStrVal("")}),
	})
	if f := (tagSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 538: variable default secrets
// ---------------------------------------------------------------------------

func Test538_VariableDefaultSecret(t *testing.T) {
	secret := "hardcoded-db-pass"
	r := dsRes("terraform_variable", "db_password", map[string]ir.Value{
		"default": dsStrVal(secret),
	})
	// Provider must be terraform for realism, but AppliesTo only checks type.
	r.Provider = "terraform"
	f := (variableDefaultSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	noSecretLeak(t, f, secret)
}

func Test538_VariableNoDefault(t *testing.T) {
	r := dsRes("terraform_variable", "db_password", map[string]ir.Value{})
	r.Provider = "terraform"
	if f := (variableDefaultSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

func Test538_VariableVaultRef(t *testing.T) {
	r := dsRes("terraform_variable", "db_password", map[string]ir.Value{
		"default": dsStrVal("vault-secret-ref"),
	})
	r.Provider = "terraform"
	if f := (variableDefaultSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings for vault reference, got %d", len(f))
	}
}

func Test538_VariableCleanName(t *testing.T) {
	r := dsRes("terraform_variable", "instance_type", map[string]ir.Value{
		"default": dsStrVal("t3.micro"),
	})
	r.Provider = "terraform"
	if f := (variableDefaultSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// 539: local secrets
// ---------------------------------------------------------------------------

func Test539_LocalSecret(t *testing.T) {
	secret := "local-hardcoded-token"
	r := dsRes("terraform_locals", "locals", map[string]ir.Value{
		"api_token": dsStrVal(secret),
		"region":    dsStrVal("us-east-1"),
	})
	r.Provider = "terraform"
	f := (localSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	noSecretLeak(t, f, secret)
}

func Test539_LocalClean(t *testing.T) {
	r := dsRes("terraform_locals", "locals", map[string]ir.Value{
		"region": dsStrVal("us-east-1"),
	})
	r.Provider = "terraform"
	if f := (localSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// Pack wiring
// ---------------------------------------------------------------------------

func TestDeepSecretsRulesInIDOrder(t *testing.T) {
	rules := DeepSecretsRules()
	want := []string{
		"AEGIS-AWS-534", "AEGIS-AWS-535", "AEGIS-AWS-536",
		"AEGIS-AWS-537", "AEGIS-AWS-538", "AEGIS-AWS-539",
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Errorf("rule %d: got %s, want %s", i, r.ID(), want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// 857: CloudFormation parameter default secrets (R4 FN class: 5 misses)
// ---------------------------------------------------------------------------

func Test857_CFNParameterDefaultSecret(t *testing.T) {
	secret := "Sup3rSecret!-prod-2024"
	r := dsRes("cfn_parameter", "DbPassword", map[string]ir.Value{
		"default": dsStrVal(secret),
	})
	r.Provider = "cfn"
	f := (cfnParameterSecret{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != ir.SeverityHigh {
		t.Errorf("expected High severity, got %v", f[0].Severity)
	}
	noSecretLeak(t, f, secret)
}

func Test857_CFNParameterNoDefault(t *testing.T) {
	r := dsRes("cfn_parameter", "DbPassword", map[string]ir.Value{})
	r.Provider = "cfn"
	if f := (cfnParameterSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}

func Test857_CFNParameterSSMRef(t *testing.T) {
	r := dsRes("cfn_parameter", "DbPassword", map[string]ir.Value{
		"default": dsStrVal("{{resolve:ssm:/prod/db/password:1}}"),
	})
	r.Provider = "cfn"
	if f := (cfnParameterSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings for SSM reference, got %d", len(f))
	}
}

func Test857_CFNParameterPlaceholder(t *testing.T) {
	r := dsRes("cfn_parameter", "DbPassword", map[string]ir.Value{
		"default": dsStrVal("changeme"),
	})
	r.Provider = "cfn"
	if f := (cfnParameterSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings for placeholder, got %d", len(f))
	}
}

func Test857_CFNParameterCleanName(t *testing.T) {
	r := dsRes("cfn_parameter", "InstanceType", map[string]ir.Value{
		"default": dsStrVal("t3.micro"),
	})
	r.Provider = "cfn"
	if f := (cfnParameterSecret{}).Check(r); len(f) != 0 {
		t.Errorf("expected no findings, got %d", len(f))
	}
}
