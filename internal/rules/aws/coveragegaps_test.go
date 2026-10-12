package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-552: IAM access key without PGP
// ---------------------------------------------------------------------------

func Test552_FiresWhenNoPGP(t *testing.T) {
	r := res("aws_iam_access_key", "k", map[string]ir.Value{})
	if fs := runRule(iamAccessKeyNoPGP{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test552_SilentWithPGP(t *testing.T) {
	r := res("aws_iam_access_key", "k", map[string]ir.Value{
		"pgp_key": ks("keybase:user", 3),
	})
	if fs := runRule(iamAccessKeyNoPGP{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-553: IAM policy NotAction + Allow
// ---------------------------------------------------------------------------

const notActionPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`
const normalPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

func Test553_FiresOnNotActionAllow(t *testing.T) {
	for _, typ := range []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"} {
		r := res(typ, "p", map[string]ir.Value{"policy": ks(notActionPolicy, 3)})
		if fs := runRule(iamPolicyNotActionAllow{}, r); len(fs) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", typ, len(fs))
		}
	}
}

func Test553_SilentOnNormal(t *testing.T) {
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(normalPolicy, 3)})
	if fs := runRule(iamPolicyNotActionAllow{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test553_SilentOnUnparseable(t *testing.T) {
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks("not json", 3)})
	if fs := runRule(iamPolicyNotActionAllow{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-554: IAM role long session
// ---------------------------------------------------------------------------

func numVal(f float64, line int) ir.Value {
	return ir.Value{Raw: f, Known: true, Span: spanAt(line)}
}

func Test554_FiresWhenTooLong(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{
		"max_session_duration": numVal(86400, 3),
	})
	if fs := runRule(iamRoleLongSession{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test554_SilentWhenOK(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{
		"max_session_duration": numVal(3600, 3),
	})
	if fs := runRule(iamRoleLongSession{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test554_SilentWhenAbsent(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{})
	if fs := runRule(iamRoleLongSession{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-555: IAM group wildcard admin
// ---------------------------------------------------------------------------

const adminPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

func Test555_FiresOnWildcard(t *testing.T) {
	r := res("aws_iam_group_policy", "p", map[string]ir.Value{"policy": ks(adminPolicy, 3)})
	if fs := runRule(iamGroupAdminPolicy{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test555_SilentOnScoped(t *testing.T) {
	r := res("aws_iam_group_policy", "p", map[string]ir.Value{"policy": ks(normalPolicy, 3)})
	if fs := runRule(iamGroupAdminPolicy{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-556: TGW propagation
// ---------------------------------------------------------------------------

func Test556_FiresWhenPresent(t *testing.T) {
	r := res("aws_ec2_transit_gateway_route_table_propagation", "p", map[string]ir.Value{})
	if fs := runRule(tgwPermissivePropagation{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

// Test556_SilentOnOtherResource: negative for AEGIS-AWS-556 — the rule is
// presence-based, so the secure configuration is the absence of a
// propagation resource: any other resource type must stay quiet.
func Test556_SilentOnOtherResource(t *testing.T) {
	r := res("aws_instance", "i", map[string]ir.Value{})
	if fs := runRule(tgwPermissivePropagation{}, r); len(fs) != 0 {
		t.Fatalf("AEGIS-AWS-556: expected 0 findings on non-propagation resource, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-557: VPC endpoint open policy
// ---------------------------------------------------------------------------

const openEndpointPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`
const scopedEndpointPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"*","Resource":"*"}]}`

func Test557_FiresOnWildcardPrincipal(t *testing.T) {
	r := res("aws_vpc_endpoint", "e", map[string]ir.Value{"policy": ks(openEndpointPolicy, 3)})
	if fs := runRule(vpcEndpointOpenPolicy{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test557_SilentOnScoped(t *testing.T) {
	r := res("aws_vpc_endpoint", "e", map[string]ir.Value{"policy": ks(scopedEndpointPolicy, 3)})
	if fs := runRule(vpcEndpointOpenPolicy{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-560: S3 force_destroy
// ---------------------------------------------------------------------------

func Test560_FiresWhenTrue(t *testing.T) {
	r := res("aws_s3_bucket", "b", map[string]ir.Value{"force_destroy": kv(true, 3)})
	if fs := runRule(s3ForceDestroy{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test560_SilentWhenFalse(t *testing.T) {
	r := res("aws_s3_bucket", "b", map[string]ir.Value{"force_destroy": kv(false, 3)})
	if fs := runRule(s3ForceDestroy{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-561: KMS short deletion window
// ---------------------------------------------------------------------------

func Test561_FiresWhenShort(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{
		"deletion_window_in_days": numVal(3, 3),
	})
	if fs := runRule(kmsShortDeletionWindow{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test561_SilentWhenOK(t *testing.T) {
	r := res("aws_kms_key", "k", map[string]ir.Value{
		"deletion_window_in_days": numVal(30, 3),
	})
	if fs := runRule(kmsShortDeletionWindow{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-562: KMS grant wildcard
// ---------------------------------------------------------------------------

func Test562_FiresOnWildcard(t *testing.T) {
	r := res("aws_kms_grant", "g", map[string]ir.Value{
		"operations": strList(3, "Encrypt", "*"),
	})
	if fs := runRule(kmsGrantWildcard{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test562_SilentOnScoped(t *testing.T) {
	r := res("aws_kms_grant", "g", map[string]ir.Value{
		"operations": strList(3, "Encrypt", "Decrypt"),
	})
	if fs := runRule(kmsGrantWildcard{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-563: Secrets Manager without CMK
// ---------------------------------------------------------------------------

func Test563_FiresWhenNoCMK(t *testing.T) {
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{})
	if fs := runRule(secretsNoCMK{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test563_SilentWithCMK(t *testing.T) {
	r := res("aws_secretsmanager_secret", "s", map[string]ir.Value{
		"kms_key_id": ks("arn:aws:kms:us-east-1:123:key/abc", 3),
	})
	if fs := runRule(secretsNoCMK{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-564: Lambda unlimited concurrency
// ---------------------------------------------------------------------------

func Test564_FiresOnMinusOne(t *testing.T) {
	r := res("aws_lambda_function", "f", map[string]ir.Value{
		"reserved_concurrent_executions": numVal(-1, 3),
	})
	if fs := runRule(lambdaUnlimitedConcurrency{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test564_SilentWhenPositive(t *testing.T) {
	r := res("aws_lambda_function", "f", map[string]ir.Value{
		"reserved_concurrent_executions": numVal(10, 3),
	})
	if fs := runRule(lambdaUnlimitedConcurrency{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test564_SilentWhenAbsent(t *testing.T) {
	// Absent is AEGIS-AWS-548's domain, not 564's.
	r := res("aws_lambda_function", "f", map[string]ir.Value{})
	if fs := runRule(lambdaUnlimitedConcurrency{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-565: EC2 EBS optimization disabled
// ---------------------------------------------------------------------------

func Test565_FiresWhenFalse(t *testing.T) {
	r := res("aws_instance", "i", map[string]ir.Value{"ebs_optimized": kv(false, 3)})
	if fs := runRule(ec2NoEBSOptimized{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test565_SilentWhenTrue(t *testing.T) {
	r := res("aws_instance", "i", map[string]ir.Value{"ebs_optimized": kv(true, 3)})
	if fs := runRule(ec2NoEBSOptimized{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-566: RDS Performance Insights without CMK
// ---------------------------------------------------------------------------

func Test566_FiresWhenEnabledNoCMK(t *testing.T) {
	r := res("aws_db_instance", "d", map[string]ir.Value{
		"performance_insights_enabled": kv(true, 3),
	})
	if fs := runRule(rdsPerfInsightsNoCMK{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test566_SilentWhenCMK(t *testing.T) {
	r := res("aws_db_instance", "d", map[string]ir.Value{
		"performance_insights_enabled":    kv(true, 3),
		"performance_insights_kms_key_id": ks("arn:aws:kms:us-east-1:123:key/abc", 4),
	})
	if fs := runRule(rdsPerfInsightsNoCMK{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test566_SilentWhenDisabled(t *testing.T) {
	r := res("aws_db_instance", "d", map[string]ir.Value{
		"performance_insights_enabled": kv(false, 3),
	})
	if fs := runRule(rdsPerfInsightsNoCMK{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-567: Security Hub not enabled
// ---------------------------------------------------------------------------

func fiveResources() []ir.Resource {
	out := make([]ir.Resource, 0, 15)
	for i := 0; i < 15; i++ {
		out = append(out, res("aws_s3_bucket", "b", map[string]ir.Value{}))
	}
	return out
}

func Test567_FiresWhenAbsent(t *testing.T) {
	fs := (noSecurityHub{}).CheckAll(fiveResources())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test567_SilentWhenPresent(t *testing.T) {
	rs := append(fiveResources(), res("aws_securityhub_account", "h", map[string]ir.Value{}))
	fs := (noSecurityHub{}).CheckAll(rs)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test567_SilentOnTrivialModule(t *testing.T) {
	fs := (noSecurityHub{}).CheckAll([]ir.Resource{res("aws_s3_bucket", "b", map[string]ir.Value{})})
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-568: CloudTrail without KMS
// ---------------------------------------------------------------------------

func Test568_FiresWhenNoKMS(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{})
	if fs := runRule(cloudtrailNoKMS{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test568_SilentWithKMS(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{
		"kms_key_id": ks("arn:aws:kms:us-east-1:123:key/abc", 3),
	})
	if fs := runRule(cloudtrailNoKMS{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-569: Detective not enabled
// ---------------------------------------------------------------------------

func Test569_FiresWhenAbsent(t *testing.T) {
	fs := (noDetective{}).CheckAll(fiveResources())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test569_SilentWhenPresent(t *testing.T) {
	rs := append(fiveResources(), res("aws_detective_graph", "d", map[string]ir.Value{}))
	fs := (noDetective{}).CheckAll(rs)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-570: CloudTrail bucket without MFA delete
// ---------------------------------------------------------------------------

func Test570_FiresWhenNoMFA(t *testing.T) {
	b := res("aws_s3_bucket", "logs", map[string]ir.Value{"bucket": ks("trail-logs", 2)})
	v := res("aws_s3_bucket_versioning", "v", map[string]ir.Value{
		"bucket":                   ks("trail-logs", 5),
		"versioning_configuration": blks(6, blk("status", ks("Enabled", 7))),
	})
	trail := res("aws_cloudtrail", "t", map[string]ir.Value{
		"s3_bucket_name": ks("trail-logs", 9),
	})
	fs := (trailBucketNoMFADelete{}).CheckAll([]ir.Resource{b, v, trail})
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test570_SilentWithMFA(t *testing.T) {
	b := res("aws_s3_bucket", "logs", map[string]ir.Value{"bucket": ks("trail-logs", 2)})
	v := res("aws_s3_bucket_versioning", "v", map[string]ir.Value{
		"bucket": ks("trail-logs", 5),
		"versioning_configuration": blks(6,
			blk("status", ks("Enabled", 7), "mfa_delete", ks("Enabled", 8))),
	})
	trail := res("aws_cloudtrail", "t", map[string]ir.Value{
		"s3_bucket_name": ks("trail-logs", 10),
	})
	fs := (trailBucketNoMFADelete{}).CheckAll([]ir.Resource{b, v, trail})
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-571: CodeArtifact without upstream
// ---------------------------------------------------------------------------

func Test571_FiresWhenNoUpstream(t *testing.T) {
	r := res("aws_codeartifact_repository", "r", map[string]ir.Value{})
	if fs := runRule(codeartifactNoUpstream{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test571_SilentWithUpstream(t *testing.T) {
	r := res("aws_codeartifact_repository", "r", map[string]ir.Value{
		"upstream": blks(3, blk("repository_name", ks("upstream-repo", 4))),
	})
	if fs := runRule(codeartifactNoUpstream{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test557_AbsentFires(t *testing.T) {
	// Absent policy: the default endpoint policy allows full access.
	r := res("aws_vpc_endpoint", "e", map[string]ir.Value{})
	if fs := runRule(vpcEndpointOpenPolicy{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}
