package aws

import (
	"testing"

	"aegis/internal/ir"
)

// Effectiveness audit (ITEM 3): hand-written pos+neg tests for rules the
// black-box probe could not drive (enum values / block shapes outside its
// battery) and regression tests for rules fixed by this audit.
// Generated replay tests for probe-covered rules live below, appended by
// the audit generator. Helpers with the ea- prefix are local to this file;
// kv/ks/ku/kn/blk/blks/strList/res/runRule come from fixtures_test.go.

// eaNum builds a known numeric value.
func eaNum(n float64, line int) ir.Value {
	return ir.Value{Raw: n, Known: true, Span: spanAt(line)}
}

// AEGIS-AWS-309: deprecated launch configuration. The rule fires on the
// mere existence of an aws_launch_configuration (no attribute is read), so
// the negative case is a resource type the rule does not apply to.
func TestEffectiveness_AWS309_LaunchConfigurationDeprecated(t *testing.T) {
	pos := res("aws_launch_configuration", "old", map[string]ir.Value{})
	if got := runRule(launchConfigurationDeprecated{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_launch_template", "new", map[string]ir.Value{})
	if got := runRule(launchConfigurationDeprecated{}, neg); len(got) != 0 {
		t.Fatalf("launch template must not fire 309, got %d", len(got))
	}
	// Unknown attributes are irrelevant: the rule reads no value.
	withUnknown := res("aws_launch_configuration", "old", map[string]ir.Value{"image_id": ku(2)})
	if got := runRule(launchConfigurationDeprecated{}, withUnknown); len(got) != 1 {
		t.Fatalf("existence rule must still fire with unknown attrs, got %d", len(got))
	}
}

// AEGIS-AWS-657/658/659: inline policy resources. The rule fires on the
// existence of the inline-policy resource type itself (iamDeepFinding
// reads no attribute), so the negative case is a different resource type.
func TestEffectiveness_AWS657_659_InlinePolicies(t *testing.T) {
	cases := []struct {
		rule  ir.Rule
		typ   string
		other string
	}{
		{iamGroupInlinePolicy{}, "aws_iam_group_policy", "aws_iam_policy"},
		{iamRoleInlinePolicy{}, "aws_iam_role_policy", "aws_iam_policy"},
		{iamUserInlinePolicy{}, "aws_iam_user_policy", "aws_iam_policy"},
	}
	for _, c := range cases {
		pos := res(c.typ, "p", map[string]ir.Value{"policy": ks(`{"Statement":[]}`, 2)})
		if got := runRule(c.rule, pos); len(got) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", c.rule.ID(), len(got))
		}
		neg := res(c.other, "p", map[string]ir.Value{"policy": ks(`{"Statement":[]}`, 2)})
		if got := runRule(c.rule, neg); len(got) != 0 {
			t.Fatalf("%s: %s must not fire, got %d", c.rule.ID(), c.other, len(got))
		}
		// Unknown policy: existence rule, still fires by design.
		unk := res(c.typ, "p", map[string]ir.Value{"policy": ku(2)})
		if got := runRule(c.rule, unk); len(got) != 1 {
			t.Fatalf("%s: existence rule must still fire on unknown policy, got %d", c.rule.ID(), len(got))
		}
	}
}

// AEGIS-AWS-662: IAM account alias missing. Cross-resource: fires when a
// password policy exists but no aws_iam_account_alias does.
func TestEffectiveness_AWS662_AccountAliasMissing(t *testing.T) {
	policy := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"minimum_password_length": kn(14, 2),
	})
	if got := (iamAccountAliasMissing{}).CheckAll([]ir.Resource{policy}); len(got) != 1 {
		t.Fatalf("expected 1 finding without alias, got %d", len(got))
	}
	alias := res("aws_iam_account_alias", "a", map[string]ir.Value{"account_alias": ks("acme", 2)})
	if got := (iamAccountAliasMissing{}).CheckAll([]ir.Resource{policy, alias}); len(got) != 0 {
		t.Fatalf("alias present must be quiet, got %d", len(got))
	}
	if got := (iamAccountAliasMissing{}).CheckAll([]ir.Resource{alias}); len(got) != 0 {
		t.Fatalf("no password policy must be quiet, got %d", len(got))
	}
	// Fully-unknown anchor config is undecidable: quiet.
	unkPolicy := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"minimum_password_length": ku(2),
	})
	if got := (iamAccountAliasMissing{}).CheckAll([]ir.Resource{unkPolicy}); len(got) != 0 {
		t.Fatalf("all-unknown anchor must be quiet, got %d", len(got))
	}
}

// AEGIS-AWS-680: EC2 instance exposes resource tags to IMDS.
func TestEffectiveness_AWS680_IMDSTagsExposed(t *testing.T) {
	pos := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("instance_metadata_tags", ks("enabled", 3))),
	})
	if got := runRule(ec2IMDSTagsExposed{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("instance_metadata_tags", ks("disabled", 3))),
	})
	if got := runRule(ec2IMDSTagsExposed{}, neg); len(got) != 0 {
		t.Fatalf("disabled must be quiet, got %d", len(got))
	}
	if got := runRule(ec2IMDSTagsExposed{}, res("aws_instance", "web", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent block must be quiet, got %d", len(got))
	}
	unk := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("instance_metadata_tags", ku(3))),
	})
	if got := runRule(ec2IMDSTagsExposed{}, unk); len(got) != 0 {
		t.Fatalf("unknown tags flag must be quiet, got %d", len(got))
	}
}

// AEGIS-AWS-681: EC2 IMDS hop limit above 1.
func TestEffectiveness_AWS681_IMDSHopLimit(t *testing.T) {
	pos := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("http_put_response_hop_limit", eaNum(2, 3))),
	})
	if got := runRule(ec2IMDSHopLimitTooHigh{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("http_put_response_hop_limit", eaNum(1, 3))),
	})
	if got := runRule(ec2IMDSHopLimitTooHigh{}, neg); len(got) != 0 {
		t.Fatalf("hop limit 1 must be quiet, got %d", len(got))
	}
	if got := runRule(ec2IMDSHopLimitTooHigh{}, res("aws_instance", "web", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent block must be quiet, got %d", len(got))
	}
	unk := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("http_put_response_hop_limit", ku(3))),
	})
	if got := runRule(ec2IMDSHopLimitTooHigh{}, unk); len(got) != 0 {
		t.Fatalf("unknown hop limit must be quiet, got %d", len(got))
	}
}

// AEGIS-AWS-690: ASG with EC2-only health checks.
func TestEffectiveness_AWS690_ASGHealthCheckEC2Only(t *testing.T) {
	pos := res("aws_autoscaling_group", "asg", map[string]ir.Value{"health_check_type": ks("EC2", 2)})
	if got := runRule(asgHealthCheckEC2Only{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_autoscaling_group", "asg", map[string]ir.Value{"health_check_type": ks("ELB", 2)})
	if got := runRule(asgHealthCheckEC2Only{}, neg); len(got) != 0 {
		t.Fatalf("ELB must be quiet, got %d", len(got))
	}
	unk := res("aws_autoscaling_group", "asg", map[string]ir.Value{"health_check_type": ku(2)})
	if got := runRule(asgHealthCheckEC2Only{}, unk); len(got) != 0 {
		t.Fatalf("unknown health_check_type must be quiet, got %d", len(got))
	}
}

// AEGIS-AWS-693: burstable instance with unlimited CPU credits.
func TestEffectiveness_AWS693_UnlimitedCPUCredits(t *testing.T) {
	pos := res("aws_instance", "web", map[string]ir.Value{
		"credit_specification": blks(2, blk("cpu_credits", ks("unlimited", 3))),
	})
	if got := runRule(ec2UnlimitedCPUCredits{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_instance", "web", map[string]ir.Value{
		"credit_specification": blks(2, blk("cpu_credits", ks("standard", 3))),
	})
	if got := runRule(ec2UnlimitedCPUCredits{}, neg); len(got) != 0 {
		t.Fatalf("standard must be quiet, got %d", len(got))
	}
	if got := runRule(ec2UnlimitedCPUCredits{}, res("aws_instance", "web", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent block must be quiet, got %d", len(got))
	}
}

// AEGIS-AWS-817: App Runner service with root-path health check.
func TestEffectiveness_AWS817_AppRunnerRootHealthCheck(t *testing.T) {
	pos := res("aws_apprunner_service", "svc", map[string]ir.Value{
		"health_check": blks(2, blk("path", ks("/", 3))),
	})
	if got := runRule(apprunnerRootHealthCheck{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_apprunner_service", "svc", map[string]ir.Value{
		"health_check": blks(2, blk("path", ks("/healthz", 3))),
	})
	if got := runRule(apprunnerRootHealthCheck{}, neg); len(got) != 0 {
		t.Fatalf("/healthz must be quiet, got %d", len(got))
	}
	if got := runRule(apprunnerRootHealthCheck{}, res("aws_apprunner_service", "svc", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent block must be quiet, got %d", len(got))
	}
}

// AEGIS-AWS-827: CloudFront distribution on the all-edge price class.
func TestEffectiveness_AWS827_CloudFrontPriceClassAll(t *testing.T) {
	pos := res("aws_cloudfront_distribution", "d", map[string]ir.Value{"price_class": ks("PriceClass_All", 2)})
	if got := runRule(cloudfrontPriceClassAll{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_cloudfront_distribution", "d", map[string]ir.Value{"price_class": ks("PriceClass_200", 2)})
	if got := runRule(cloudfrontPriceClassAll{}, neg); len(got) != 0 {
		t.Fatalf("PriceClass_200 must be quiet, got %d", len(got))
	}
	unk := res("aws_cloudfront_distribution", "d", map[string]ir.Value{"price_class": ku(2)})
	if got := runRule(cloudfrontPriceClassAll{}, unk); len(got) != 0 {
		t.Fatalf("unknown price_class must be quiet, got %d", len(got))
	}
}

// AEGIS-AWS-839: ACM certificate with transparency logging disabled.
func TestEffectiveness_AWS839_ACMNoTransparencyLogging(t *testing.T) {
	pos := res("aws_acm_certificate", "c", map[string]ir.Value{
		"options": blks(2, blk("certificate_transparency_logging_preference", ks("DISABLED", 3))),
	})
	if got := runRule(acmNoTransparencyLogging{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_acm_certificate", "c", map[string]ir.Value{
		"options": blks(2, blk("certificate_transparency_logging_preference", ks("ENABLED", 3))),
	})
	if got := runRule(acmNoTransparencyLogging{}, neg); len(got) != 0 {
		t.Fatalf("ENABLED must be quiet, got %d", len(got))
	}
	if got := runRule(acmNoTransparencyLogging{}, res("aws_acm_certificate", "c", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent options must be quiet (provider default ENABLED), got %d", len(got))
	}
}

// AEGIS-AWS-842: ALB listener with an outdated SSL policy.
func TestEffectiveness_AWS842_ALBListenerOldSSLPolicy(t *testing.T) {
	pos := res("aws_lb_listener", "l", map[string]ir.Value{"ssl_policy": ks("ELBSecurityPolicy-2016-08", 2)})
	if got := runRule(albListenerOldSSLPolicy{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_lb_listener", "l", map[string]ir.Value{"ssl_policy": ks("ELBSecurityPolicy-TLS13-1-2-2021-06", 2)})
	if got := runRule(albListenerOldSSLPolicy{}, neg); len(got) != 0 {
		t.Fatalf("current policy must be quiet, got %d", len(got))
	}
	if got := runRule(albListenerOldSSLPolicy{}, res("aws_lb_listener", "l", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent policy must be quiet (provider default is current), got %d", len(got))
	}
}

// AEGIS-AWS-847: DLM lifecycle policy disabled.
func TestEffectiveness_AWS847_DLMPolicyDisabled(t *testing.T) {
	pos := res("aws_dlm_lifecycle_policy", "p", map[string]ir.Value{"state": ks("DISABLED", 2)})
	if got := runRule(dlmPolicyDisabled{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("aws_dlm_lifecycle_policy", "p", map[string]ir.Value{"state": ks("ENABLED", 2)})
	if got := runRule(dlmPolicyDisabled{}, neg); len(got) != 0 {
		t.Fatalf("ENABLED must be quiet, got %d", len(got))
	}
	if got := runRule(dlmPolicyDisabled{}, res("aws_dlm_lifecycle_policy", "p", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent state must be quiet (provider default ENABLED), got %d", len(got))
	}
}

// ---- shared replay helpers (ea- prefix; local to this file) ----

func eaB(b bool) ir.Value { return ir.Value{Raw: b, Known: true} }

func eaS(s string) ir.Value { return ir.Value{Raw: s, Known: true} }

func eaN(n float64) ir.Value { return ir.Value{Raw: n, Known: true} }

func eaL(items ...ir.Value) ir.Value { return ir.Value{Raw: items, Known: true} }

func eaM(pairs ...any) ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	return ir.Value{Raw: m, Known: true}
}

func eaU() ir.Value { return ir.Value{Known: false} }

func eaRes(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{Type: typ, Name: name, Provider: "audit", Attributes: attrs}
}

// eaRun evaluates rule the way the engine does: CheckAll for
// cross-resource rules, Check per applicable resource otherwise.
func eaRun(rule ir.Rule, resources ...ir.Resource) []ir.Finding {
	var out []ir.Finding
	if cr, ok := rule.(ir.CrossResourceRule); ok {
		out = append(out, cr.CheckAll(resources)...)
	} else {
		for _, r := range resources {
			if rule.AppliesTo(r.Type) {
				out = append(out, rule.Check(r)...)
			}
		}
	}
	var filtered []ir.Finding
	for _, f := range out {
		if f.RuleID == rule.ID() {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// eaRuleFor looks a rule up by ID in this pack's registry.
func eaRuleFor(t *testing.T, id string) ir.Rule {
	t.Helper()
	for _, r := range Rules() {
		if r.ID() == id {
			return r
		}
	}
	t.Fatalf("rule %s not found in pack registry", id)
	return nil
}
func TestEffectivenessReplay_AWS_104(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-104")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_s3_bucket", "probe", map[string]ir.Value{
			"Action":               eaS("public-read"),
			"Allow":                eaS("public-read"),
			"Effect":               eaS("public-read"),
			"NotPrincipal":         eaS("public-read"),
			"Principal":            eaS("public-read"),
			"Statement":            eaS("public-read"),
			"acl":                  eaS("public-read"),
			"aws_":                 eaS("public-read"),
			"aws_s3_bucket":        eaS("public-read"),
			"aws_s3_bucket_acl":    eaS("public-read"),
			"aws_s3_bucket_policy": eaS("public-read"),
			"bucket":               eaS("public-read"),
			"cidr_blocks":          eaS("public-read"),
			"cidr_ipv4":            eaS("public-read"),
			"ingress":              eaS("public-read"),
			"internet":             eaS("public-read"),
			"module":               eaS("public-read"),
			"policy":               eaS("public-read"),
			"publicly_accessible":  eaS("public-read"),
			"security_group_id":    eaS("public-read"),
			"type":                 eaS("public-read"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-104: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-104: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-104: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_s3_bucket", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-104: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_s3_bucket", "probe", map[string]ir.Value{
		"Action":               eaU(),
		"Allow":                eaU(),
		"Effect":               eaU(),
		"NotPrincipal":         eaU(),
		"Principal":            eaU(),
		"Statement":            eaU(),
		"acl":                  eaU(),
		"aws_":                 eaU(),
		"aws_s3_bucket":        eaU(),
		"aws_s3_bucket_acl":    eaU(),
		"aws_s3_bucket_policy": eaU(),
		"bucket":               eaU(),
		"cidr_blocks":          eaU(),
		"cidr_ipv4":            eaU(),
		"ingress":              eaU(),
		"internet":             eaU(),
		"module":               eaU(),
		"policy":               eaU(),
		"publicly_accessible":  eaU(),
		"rule":                 eaU(),
		"security_group_id":    eaU(),
		"strings":              eaU(),
		"target_bucket":        eaU(),
		"type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-104: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_335(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-335")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_kms_key", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-335: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-335: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-335: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_kms_key", "probe", map[string]ir.Value{
			"Action":                        eaL(eaS("s3:GetObject")),
			"Allow":                         eaS("private"),
			"Effect":                        eaS("Deny"),
			"Resource":                      eaL(eaS("arn:aws:s3:::mybucket/*")),
			"SecureString":                  eaB(true),
			"Statement":                     eaS("private"),
			"String":                        eaS("private"),
			"apikey":                        eaS("P@ssw0rd!2024Strong"),
			"automatically_after_days":      eaN(365.0),
			"db_password":                   eaS("P@ssw0rd!2024Strong"),
			"enable_key_rotation":           eaB(true),
			"fsx_admin_password":            eaS("P@ssw0rd!2024Strong"),
			"hardcoded":                     eaS("private"),
			"include_global_service_events": eaS("ClusterIP"),
			"is_multi_region_trail":         eaS("us-east-1"),
			"local":                         eaS("private"),
			"master_password":               eaS("P@ssw0rd!2024Strong"),
			"minimum_password_length":       eaS("P@ssw0rd!2024Strong"),
			"name":                          eaS("app"),
			"passwd":                        eaS("P@ssw0rd!2024Strong"),
			"password":                      eaS("P@ssw0rd!2024Strong"),
			"password_reuse_prevention":     eaS("P@ssw0rd!2024Strong"),
			"policy":                        eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"require_lowercase_characters":  eaB(true),
			"require_numbers":               eaB(true),
			"require_symbols":               eaB(true),
			"require_uppercase_characters":  eaB(true),
			"rotation_rules":                eaB(true),
			"secret":                        eaS("P@ssw0rd!2024Strong"),
			"sensitive":                     eaS("private"),
			"token":                         eaS("P@ssw0rd!2024Strong"),
			"type":                          eaS("SecureString"),
			"var":                           eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-335: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_kms_key", "probe", map[string]ir.Value{
		"Action":                        eaU(),
		"Allow":                         eaU(),
		"Effect":                        eaU(),
		"Resource":                      eaU(),
		"SecureString":                  eaU(),
		"Statement":                     eaU(),
		"String":                        eaU(),
		"apikey":                        eaU(),
		"automatically_after_days":      eaU(),
		"bucket":                        eaU(),
		"db_password":                   eaU(),
		"enable_key_rotation":           eaU(),
		"false":                         eaU(),
		"fsx_admin_password":            eaU(),
		"hardcoded":                     eaU(),
		"include_global_service_events": eaU(),
		"is_multi_region_trail":         eaU(),
		"local":                         eaU(),
		"master_password":               eaU(),
		"minimum_password_length":       eaU(),
		"name":                          eaU(),
		"passwd":                        eaU(),
		"password":                      eaU(),
		"password_reuse_prevention":     eaU(),
		"policy":                        eaU(),
		"require_lowercase_characters":  eaU(),
		"require_numbers":               eaU(),
		"require_symbols":               eaU(),
		"require_uppercase_characters":  eaU(),
		"rotation_rules":                eaU(),
		"rule":                          eaU(),
		"secret":                        eaU(),
		"sensitive":                     eaU(),
		"strings":                       eaU(),
		"target_bucket":                 eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"type":                          eaU(),
		"var":                           eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-335: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_366(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-366")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_sagemaker_notebook_instance", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-366: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-366: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-366: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_sagemaker_notebook_instance", "probe", map[string]ir.Value{
			"EnableAtRestEncryption":           eaB(false),
			"EncryptionConfiguration":          eaB(false),
			"NONE":                             eaS("public"),
			"catalog_encryption_mode":          eaB(false),
			"configuration":                    eaS("public"),
			"data_catalog_encryption_settings": eaB(false),
			"empty":                            eaS("public"),
			"encryption_at_rest":               eaB(false),
			"encryption_configuration":         eaB(false),
			"encryption_option":                eaB(false),
			"kms_key_arn":                      eaS("password123"),
			"kms_key_id":                       eaS("password123"),
			"result_configuration":             eaS("public"),
			"server_side_encryption":           eaB(false),
			"visible_to_all_users":             eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-366: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_sagemaker_notebook_instance", "probe", map[string]ir.Value{
		"EnableAtRestEncryption":           eaU(),
		"EncryptionConfiguration":          eaU(),
		"NONE":                             eaU(),
		"bucket":                           eaU(),
		"catalog_encryption_mode":          eaU(),
		"configuration":                    eaU(),
		"data_catalog_encryption_settings": eaU(),
		"empty":                            eaU(),
		"encryption_at_rest":               eaU(),
		"encryption_configuration":         eaU(),
		"encryption_option":                eaU(),
		"false":                            eaU(),
		"kms_key_arn":                      eaU(),
		"kms_key_id":                       eaU(),
		"result_configuration":             eaU(),
		"rule":                             eaU(),
		"server_side_encryption":           eaU(),
		"strings":                          eaU(),
		"target_bucket":                    eaU(),
		"true":                             eaU(),
		"visible_to_all_users":             eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-366: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_367(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-367")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_sagemaker_endpoint_configuration", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-367: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-367: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-367: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_sagemaker_endpoint_configuration", "probe", map[string]ir.Value{
			"EnableAtRestEncryption":           eaB(false),
			"EncryptionConfiguration":          eaB(false),
			"NONE":                             eaS("public"),
			"catalog_encryption_mode":          eaB(false),
			"configuration":                    eaS("public"),
			"data_catalog_encryption_settings": eaB(false),
			"empty":                            eaS("public"),
			"encryption_at_rest":               eaB(false),
			"encryption_configuration":         eaB(false),
			"encryption_option":                eaB(false),
			"kms_key_arn":                      eaS("password123"),
			"kms_key_id":                       eaS("password123"),
			"result_configuration":             eaS("public"),
			"server_side_encryption":           eaB(false),
			"visible_to_all_users":             eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-367: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_sagemaker_endpoint_configuration", "probe", map[string]ir.Value{
		"EnableAtRestEncryption":           eaU(),
		"EncryptionConfiguration":          eaU(),
		"NONE":                             eaU(),
		"bucket":                           eaU(),
		"catalog_encryption_mode":          eaU(),
		"configuration":                    eaU(),
		"data_catalog_encryption_settings": eaU(),
		"empty":                            eaU(),
		"encryption_at_rest":               eaU(),
		"encryption_configuration":         eaU(),
		"encryption_option":                eaU(),
		"false":                            eaU(),
		"kms_key_arn":                      eaU(),
		"kms_key_id":                       eaU(),
		"result_configuration":             eaU(),
		"rule":                             eaU(),
		"server_side_encryption":           eaU(),
		"strings":                          eaU(),
		"target_bucket":                    eaU(),
		"true":                             eaU(),
		"visible_to_all_users":             eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-367: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_368(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-368")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_fsx_windows_file_system", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-368: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-368: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-368: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_fsx_windows_file_system", "probe", map[string]ir.Value{
			"EnableAtRestEncryption":           eaB(false),
			"EncryptionConfiguration":          eaB(false),
			"NONE":                             eaS("public"),
			"catalog_encryption_mode":          eaB(false),
			"configuration":                    eaS("public"),
			"data_catalog_encryption_settings": eaB(false),
			"empty":                            eaS("public"),
			"encryption_at_rest":               eaB(false),
			"encryption_configuration":         eaB(false),
			"encryption_option":                eaB(false),
			"kms_key_arn":                      eaS("password123"),
			"kms_key_id":                       eaS("password123"),
			"result_configuration":             eaS("public"),
			"server_side_encryption":           eaB(false),
			"visible_to_all_users":             eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-368: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_fsx_windows_file_system", "probe", map[string]ir.Value{
		"EnableAtRestEncryption":           eaU(),
		"EncryptionConfiguration":          eaU(),
		"NONE":                             eaU(),
		"bucket":                           eaU(),
		"catalog_encryption_mode":          eaU(),
		"configuration":                    eaU(),
		"data_catalog_encryption_settings": eaU(),
		"empty":                            eaU(),
		"encryption_at_rest":               eaU(),
		"encryption_configuration":         eaU(),
		"encryption_option":                eaU(),
		"false":                            eaU(),
		"kms_key_arn":                      eaU(),
		"kms_key_id":                       eaU(),
		"result_configuration":             eaU(),
		"rule":                             eaU(),
		"server_side_encryption":           eaU(),
		"strings":                          eaU(),
		"target_bucket":                    eaU(),
		"true":                             eaU(),
		"visible_to_all_users":             eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-368: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_369(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-369")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_fsx_lustre_file_system", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-369: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-369: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-369: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_fsx_lustre_file_system", "probe", map[string]ir.Value{
			"EnableAtRestEncryption":           eaB(false),
			"EncryptionConfiguration":          eaB(false),
			"NONE":                             eaS("public"),
			"catalog_encryption_mode":          eaB(false),
			"configuration":                    eaS("public"),
			"data_catalog_encryption_settings": eaB(false),
			"empty":                            eaS("public"),
			"encryption_at_rest":               eaB(false),
			"encryption_configuration":         eaB(false),
			"encryption_option":                eaB(false),
			"kms_key_arn":                      eaS("password123"),
			"kms_key_id":                       eaS("password123"),
			"result_configuration":             eaS("public"),
			"server_side_encryption":           eaB(false),
			"visible_to_all_users":             eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-369: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_fsx_lustre_file_system", "probe", map[string]ir.Value{
		"EnableAtRestEncryption":           eaU(),
		"EncryptionConfiguration":          eaU(),
		"NONE":                             eaU(),
		"bucket":                           eaU(),
		"catalog_encryption_mode":          eaU(),
		"configuration":                    eaU(),
		"data_catalog_encryption_settings": eaU(),
		"empty":                            eaU(),
		"encryption_at_rest":               eaU(),
		"encryption_configuration":         eaU(),
		"encryption_option":                eaU(),
		"false":                            eaU(),
		"kms_key_arn":                      eaU(),
		"kms_key_id":                       eaU(),
		"result_configuration":             eaU(),
		"rule":                             eaU(),
		"server_side_encryption":           eaU(),
		"strings":                          eaU(),
		"target_bucket":                    eaU(),
		"true":                             eaU(),
		"visible_to_all_users":             eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-369: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_370(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-370")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_sagemaker_domain", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-370: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-370: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-370: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_sagemaker_domain", "probe", map[string]ir.Value{
			"EnableAtRestEncryption":           eaB(false),
			"EncryptionConfiguration":          eaB(false),
			"NONE":                             eaS("public"),
			"catalog_encryption_mode":          eaB(false),
			"configuration":                    eaS("public"),
			"data_catalog_encryption_settings": eaB(false),
			"empty":                            eaS("public"),
			"encryption_at_rest":               eaB(false),
			"encryption_configuration":         eaB(false),
			"encryption_option":                eaB(false),
			"kms_key_arn":                      eaS("password123"),
			"kms_key_id":                       eaS("password123"),
			"result_configuration":             eaS("public"),
			"server_side_encryption":           eaB(false),
			"visible_to_all_users":             eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-370: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_sagemaker_domain", "probe", map[string]ir.Value{
		"EnableAtRestEncryption":           eaU(),
		"EncryptionConfiguration":          eaU(),
		"NONE":                             eaU(),
		"bucket":                           eaU(),
		"catalog_encryption_mode":          eaU(),
		"configuration":                    eaU(),
		"data_catalog_encryption_settings": eaU(),
		"empty":                            eaU(),
		"encryption_at_rest":               eaU(),
		"encryption_configuration":         eaU(),
		"encryption_option":                eaU(),
		"false":                            eaU(),
		"kms_key_arn":                      eaU(),
		"kms_key_id":                       eaU(),
		"result_configuration":             eaU(),
		"rule":                             eaU(),
		"server_side_encryption":           eaU(),
		"strings":                          eaU(),
		"target_bucket":                    eaU(),
		"true":                             eaU(),
		"visible_to_all_users":             eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-370: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_534(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-534")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_autoscaling_group", "probe", map[string]ir.Value{
			"aws_":             eaS("AKIAIOSFODNN7EXAMPLE"),
			"connection":       eaS("AKIAIOSFODNN7EXAMPLE"),
			"default":          eaS("AKIAIOSFODNN7EXAMPLE"),
			"keyvault":         eaS("AKIAIOSFODNN7EXAMPLE"),
			"password":         eaS("AKIAIOSFODNN7EXAMPLE"),
			"provisioner":      eaS("AKIAIOSFODNN7EXAMPLE"),
			"secretsmanager":   eaS("AKIAIOSFODNN7EXAMPLE"),
			"sensitive":        eaS("AKIAIOSFODNN7EXAMPLE"),
			"ssm":              eaS("AKIAIOSFODNN7EXAMPLE"),
			"tags":             eaS("AKIAIOSFODNN7EXAMPLE"),
			"user_data":        eaS("AKIAIOSFODNN7EXAMPLE"),
			"user_data_base64": eaS("AKIAIOSFODNN7EXAMPLE"),
			"value":            eaS("AKIAIOSFODNN7EXAMPLE"),
			"vault":            eaS("AKIAIOSFODNN7EXAMPLE"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-534: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-534: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-534: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_autoscaling_group", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-534: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_autoscaling_group", "probe", map[string]ir.Value{
		"aws_":             eaU(),
		"bucket":           eaU(),
		"connection":       eaU(),
		"default":          eaU(),
		"keyvault":         eaU(),
		"password":         eaU(),
		"provisioner":      eaU(),
		"rule":             eaU(),
		"secretsmanager":   eaU(),
		"sensitive":        eaU(),
		"ssm":              eaU(),
		"strings":          eaU(),
		"tags":             eaU(),
		"target_bucket":    eaU(),
		"user_data":        eaU(),
		"user_data_base64": eaU(),
		"value":            eaU(),
		"vault":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-534: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_535(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-535")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_s3_bucket", "probe", map[string]ir.Value{
			"provisioner": eaL(eaM("connection", eaL(eaM("aws_", eaS("*"), "connection", eaS("*"), "default", eaS("*"), "keyvault", eaS("*"), "password", eaS("*"), "provisioner", eaS("*"), "secretsmanager", eaS("*"), "sensitive", eaS("*"), "ssm", eaS("*"), "tags", eaS("*"), "user_data", eaS("*"), "user_data_base64", eaS("*"), "value", eaS("*"), "vault", eaS("*"))))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-535: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-535: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-535: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_s3_bucket", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-535: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_s3_bucket", "probe", map[string]ir.Value{
		"aws_":             eaU(),
		"bucket":           eaU(),
		"connection":       eaU(),
		"default":          eaU(),
		"keyvault":         eaU(),
		"password":         eaU(),
		"provisioner":      eaU(),
		"rule":             eaU(),
		"secretsmanager":   eaU(),
		"sensitive":        eaU(),
		"ssm":              eaU(),
		"strings":          eaU(),
		"tags":             eaU(),
		"target_bucket":    eaU(),
		"user_data":        eaU(),
		"user_data_base64": eaU(),
		"value":            eaU(),
		"vault":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-535: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_536(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-536")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("terraform_output", "my_password", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-536: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-536: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-536: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("terraform_output", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-536: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("terraform_output", "probe", map[string]ir.Value{
		"aws_":             eaU(),
		"bucket":           eaU(),
		"connection":       eaU(),
		"default":          eaU(),
		"keyvault":         eaU(),
		"password":         eaU(),
		"provisioner":      eaU(),
		"rule":             eaU(),
		"secretsmanager":   eaU(),
		"sensitive":        eaU(),
		"ssm":              eaU(),
		"strings":          eaU(),
		"tags":             eaU(),
		"target_bucket":    eaU(),
		"user_data":        eaU(),
		"user_data_base64": eaU(),
		"value":            eaU(),
		"vault":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-536: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_537(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-537")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_s3_bucket", "probe", map[string]ir.Value{
			"tags": eaM("aws_", eaS("public"), "connection", eaS("public"), "default", eaS("public"), "keyvault", eaS("password123"), "password", eaS("password123"), "provisioner", eaS("public"), "secretsmanager", eaS("password123"), "sensitive", eaS("public"), "ssm", eaS("public"), "tags", eaS("latest"), "user_data", eaS("curl https://example.com/install.sh | sh"), "user_data_base64", eaS("curl https://example.com/install.sh | sh"), "value", eaS("public"), "vault", eaS("public")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-537: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-537: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-537: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_s3_bucket", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-537: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_s3_bucket", "probe", map[string]ir.Value{
		"aws_":             eaU(),
		"bucket":           eaU(),
		"connection":       eaU(),
		"default":          eaU(),
		"keyvault":         eaU(),
		"password":         eaU(),
		"provisioner":      eaU(),
		"rule":             eaU(),
		"secretsmanager":   eaU(),
		"sensitive":        eaU(),
		"ssm":              eaU(),
		"strings":          eaU(),
		"tags":             eaU(),
		"target_bucket":    eaU(),
		"user_data":        eaU(),
		"user_data_base64": eaU(),
		"value":            eaU(),
		"vault":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-537: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_538(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-538")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("terraform_variable", "my_password", map[string]ir.Value{
			"aws_":             eaS("0.0.0.0/0"),
			"connection":       eaS("0.0.0.0/0"),
			"default":          eaS("0.0.0.0/0"),
			"keyvault":         eaS("0.0.0.0/0"),
			"password":         eaS("0.0.0.0/0"),
			"provisioner":      eaS("0.0.0.0/0"),
			"secretsmanager":   eaS("0.0.0.0/0"),
			"sensitive":        eaS("0.0.0.0/0"),
			"ssm":              eaS("0.0.0.0/0"),
			"tags":             eaS("0.0.0.0/0"),
			"user_data":        eaS("0.0.0.0/0"),
			"user_data_base64": eaS("0.0.0.0/0"),
			"value":            eaS("0.0.0.0/0"),
			"vault":            eaS("0.0.0.0/0"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-538: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-538: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-538: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("terraform_variable", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-538: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("terraform_variable", "probe", map[string]ir.Value{
		"aws_":             eaU(),
		"bucket":           eaU(),
		"connection":       eaU(),
		"default":          eaU(),
		"keyvault":         eaU(),
		"password":         eaU(),
		"provisioner":      eaU(),
		"rule":             eaU(),
		"secretsmanager":   eaU(),
		"sensitive":        eaU(),
		"ssm":              eaU(),
		"strings":          eaU(),
		"tags":             eaU(),
		"target_bucket":    eaU(),
		"user_data":        eaU(),
		"user_data_base64": eaU(),
		"value":            eaU(),
		"vault":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-538: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_539(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-539")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("terraform_locals", "probe", map[string]ir.Value{
			"aws_":             eaS("public"),
			"connection":       eaS("public"),
			"default":          eaS("public"),
			"keyvault":         eaS("password123"),
			"password":         eaS("password123"),
			"provisioner":      eaS("public"),
			"secretsmanager":   eaS("password123"),
			"sensitive":        eaS("public"),
			"ssm":              eaS("public"),
			"tags":             eaS("latest"),
			"user_data":        eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64": eaS("curl https://example.com/install.sh | sh"),
			"value":            eaS("public"),
			"vault":            eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-539: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-539: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-539: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("terraform_locals", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-539: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("terraform_locals", "probe", map[string]ir.Value{
		"aws_":             eaU(),
		"bucket":           eaU(),
		"connection":       eaU(),
		"default":          eaU(),
		"keyvault":         eaU(),
		"password":         eaU(),
		"provisioner":      eaU(),
		"rule":             eaU(),
		"secretsmanager":   eaU(),
		"sensitive":        eaU(),
		"ssm":              eaU(),
		"strings":          eaU(),
		"tags":             eaU(),
		"target_bucket":    eaU(),
		"user_data":        eaU(),
		"user_data_base64": eaU(),
		"value":            eaU(),
		"vault":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-539: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_541(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-541")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_launch_configuration", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-541: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-541: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-541: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_launch_configuration", "probe", map[string]ir.Value{
			"absent":                              eaS("public"),
			"aurora":                              eaS("public"),
			"auto_minor_version_upgrade":          eaS(">= 1.0"),
			"enabled_cloudwatch_logs_exports":     eaS("3389"),
			"engine":                              eaS("public"),
			"http_tokens":                         eaS("password123"),
			"iam_database_authentication_enabled": eaB(false),
			"metadata_options":                    eaS("public"),
			"mysql":                               eaS("public"),
			"postgres":                            eaS("public"),
			"required":                            eaB(false),
			"rule":                                eaS("public"),
			"vpc_config":                          eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-541: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_launch_configuration", "probe", map[string]ir.Value{
		"absent":                              eaU(),
		"aurora":                              eaU(),
		"auto_minor_version_upgrade":          eaU(),
		"bucket":                              eaU(),
		"enabled_cloudwatch_logs_exports":     eaU(),
		"engine":                              eaU(),
		"false":                               eaU(),
		"http_tokens":                         eaU(),
		"iam_database_authentication_enabled": eaU(),
		"metadata_options":                    eaU(),
		"mysql":                               eaU(),
		"postgres":                            eaU(),
		"required":                            eaU(),
		"rule":                                eaU(),
		"strings":                             eaU(),
		"target_bucket":                       eaU(),
		"vpc_config":                          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-541: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_542(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-542")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_lambda_function", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-542: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-542: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-542: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_lambda_function", "probe", map[string]ir.Value{
			"absent":                              eaS("public"),
			"aurora":                              eaS("public"),
			"auto_minor_version_upgrade":          eaS(">= 1.0"),
			"enabled_cloudwatch_logs_exports":     eaS("3389"),
			"engine":                              eaS("public"),
			"http_tokens":                         eaS("password123"),
			"iam_database_authentication_enabled": eaB(false),
			"metadata_options":                    eaS("public"),
			"mysql":                               eaS("public"),
			"postgres":                            eaS("public"),
			"required":                            eaB(false),
			"rule":                                eaS("public"),
			"vpc_config":                          eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-542: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_lambda_function", "probe", map[string]ir.Value{
		"absent":                              eaU(),
		"aurora":                              eaU(),
		"auto_minor_version_upgrade":          eaU(),
		"bucket":                              eaU(),
		"enabled_cloudwatch_logs_exports":     eaU(),
		"engine":                              eaU(),
		"false":                               eaU(),
		"http_tokens":                         eaU(),
		"iam_database_authentication_enabled": eaU(),
		"metadata_options":                    eaU(),
		"mysql":                               eaU(),
		"postgres":                            eaU(),
		"required":                            eaU(),
		"rule":                                eaU(),
		"strings":                             eaU(),
		"target_bucket":                       eaU(),
		"vpc_config":                          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-542: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_651(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-651")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-651: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-651: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-651: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{
			"Action":                       eaL(eaS("s3:GetObject")),
			"Active":                       eaS("private"),
			"Allow":                        eaS("private"),
			"Condition":                    eaS("private"),
			"Effect":                       eaS("Deny"),
			"NotAction":                    eaL(eaS("s3:GetObject")),
			"NotResource":                  eaL(eaS("arn:aws:s3:::mybucket/*")),
			"Resource":                     eaL(eaS("arn:aws:s3:::mybucket/*")),
			"Sid":                          eaS("private"),
			"account_alias":                eaN(30.0),
			"admin":                        eaB(false),
			"administratoraccess":          eaS("Deny"),
			"assume_role_policy":           eaS("roles/viewer"),
			"aws_iam_account_alias":        eaN(30.0),
			"description":                  eaS("private"),
			"empty":                        eaS("private"),
			"force_destroy":                eaS("private"),
			"force_detach_policies":        eaS("private"),
			"hard_expiry":                  eaS("private"),
			"managed_policy_arns":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"max_password_age":             eaS("P@ssw0rd!2024Strong"),
			"minimum_password_length":      eaS("P@ssw0rd!2024Strong"),
			"name":                         eaS("app"),
			"password_reset_required":      eaS("P@ssw0rd!2024Strong"),
			"password_reuse_prevention":    eaS("P@ssw0rd!2024Strong"),
			"permissions_boundary":         eaS("private"),
			"pgp_key":                      eaS("P@ssw0rd!2024Strong"),
			"policy":                       eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"policy_arn":                   eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"poweruseraccess":              eaS("Deny"),
			"prod":                         eaS("private"),
			"readonlyaccess":               eaS("Deny"),
			"require_lowercase_characters": eaB(true),
			"require_numbers":              eaB(true),
			"require_symbols":              eaB(true),
			"require_uppercase_characters": eaB(true),
			"status":                       eaS("private"),
			"tags":                         eaS("1.2.3"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-651: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{
		"Action":                       eaU(),
		"Active":                       eaU(),
		"Allow":                        eaU(),
		"Condition":                    eaU(),
		"Effect":                       eaU(),
		"NotAction":                    eaU(),
		"NotResource":                  eaU(),
		"Resource":                     eaU(),
		"Sid":                          eaU(),
		"account_alias":                eaU(),
		"admin":                        eaU(),
		"administratoraccess":          eaU(),
		"assume_role_policy":           eaU(),
		"aws_iam_account_alias":        eaU(),
		"bucket":                       eaU(),
		"description":                  eaU(),
		"empty":                        eaU(),
		"false":                        eaU(),
		"force_destroy":                eaU(),
		"force_detach_policies":        eaU(),
		"hard_expiry":                  eaU(),
		"managed_policy_arns":          eaU(),
		"max_password_age":             eaU(),
		"minimum_password_length":      eaU(),
		"name":                         eaU(),
		"password_reset_required":      eaU(),
		"password_reuse_prevention":    eaU(),
		"permissions_boundary":         eaU(),
		"pgp_key":                      eaU(),
		"policy":                       eaU(),
		"policy_arn":                   eaU(),
		"poweruseraccess":              eaU(),
		"prod":                         eaU(),
		"readonlyaccess":               eaU(),
		"require_lowercase_characters": eaU(),
		"require_numbers":              eaU(),
		"require_symbols":              eaU(),
		"require_uppercase_characters": eaU(),
		"rule":                         eaU(),
		"status":                       eaU(),
		"strings":                      eaU(),
		"tags":                         eaU(),
		"target_bucket":                eaU(),
		"true":                         eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-651: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_652(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-652")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-652: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-652: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-652: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{
			"Action":                       eaL(eaS("s3:GetObject")),
			"Active":                       eaS("private"),
			"Allow":                        eaS("private"),
			"Condition":                    eaS("private"),
			"Effect":                       eaS("Deny"),
			"NotAction":                    eaL(eaS("s3:GetObject")),
			"NotResource":                  eaL(eaS("arn:aws:s3:::mybucket/*")),
			"Resource":                     eaL(eaS("arn:aws:s3:::mybucket/*")),
			"Sid":                          eaS("private"),
			"account_alias":                eaN(30.0),
			"admin":                        eaB(false),
			"administratoraccess":          eaS("Deny"),
			"assume_role_policy":           eaS("roles/viewer"),
			"aws_iam_account_alias":        eaN(30.0),
			"description":                  eaS("private"),
			"empty":                        eaS("private"),
			"force_destroy":                eaS("private"),
			"force_detach_policies":        eaS("private"),
			"hard_expiry":                  eaS("private"),
			"managed_policy_arns":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"max_password_age":             eaS("P@ssw0rd!2024Strong"),
			"minimum_password_length":      eaS("P@ssw0rd!2024Strong"),
			"name":                         eaS("app"),
			"password_reset_required":      eaS("P@ssw0rd!2024Strong"),
			"password_reuse_prevention":    eaS("P@ssw0rd!2024Strong"),
			"permissions_boundary":         eaS("private"),
			"pgp_key":                      eaS("P@ssw0rd!2024Strong"),
			"policy":                       eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"policy_arn":                   eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"poweruseraccess":              eaS("Deny"),
			"prod":                         eaS("private"),
			"readonlyaccess":               eaS("Deny"),
			"require_lowercase_characters": eaB(true),
			"require_numbers":              eaB(true),
			"require_symbols":              eaB(true),
			"require_uppercase_characters": eaB(true),
			"status":                       eaS("private"),
			"tags":                         eaS("1.2.3"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-652: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{
		"Action":                       eaU(),
		"Active":                       eaU(),
		"Allow":                        eaU(),
		"Condition":                    eaU(),
		"Effect":                       eaU(),
		"NotAction":                    eaU(),
		"NotResource":                  eaU(),
		"Resource":                     eaU(),
		"Sid":                          eaU(),
		"account_alias":                eaU(),
		"admin":                        eaU(),
		"administratoraccess":          eaU(),
		"assume_role_policy":           eaU(),
		"aws_iam_account_alias":        eaU(),
		"bucket":                       eaU(),
		"description":                  eaU(),
		"empty":                        eaU(),
		"false":                        eaU(),
		"force_destroy":                eaU(),
		"force_detach_policies":        eaU(),
		"hard_expiry":                  eaU(),
		"managed_policy_arns":          eaU(),
		"max_password_age":             eaU(),
		"minimum_password_length":      eaU(),
		"name":                         eaU(),
		"password_reset_required":      eaU(),
		"password_reuse_prevention":    eaU(),
		"permissions_boundary":         eaU(),
		"pgp_key":                      eaU(),
		"policy":                       eaU(),
		"policy_arn":                   eaU(),
		"poweruseraccess":              eaU(),
		"prod":                         eaU(),
		"readonlyaccess":               eaU(),
		"require_lowercase_characters": eaU(),
		"require_numbers":              eaU(),
		"require_symbols":              eaU(),
		"require_uppercase_characters": eaU(),
		"rule":                         eaU(),
		"status":                       eaU(),
		"strings":                      eaU(),
		"tags":                         eaU(),
		"target_bucket":                eaU(),
		"true":                         eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-652: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_653(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-653")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-653: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-653: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-653: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{
			"Action":                       eaL(eaS("s3:GetObject")),
			"Active":                       eaS("private"),
			"Allow":                        eaS("private"),
			"Condition":                    eaS("private"),
			"Effect":                       eaS("Deny"),
			"NotAction":                    eaL(eaS("s3:GetObject")),
			"NotResource":                  eaL(eaS("arn:aws:s3:::mybucket/*")),
			"Resource":                     eaL(eaS("arn:aws:s3:::mybucket/*")),
			"Sid":                          eaS("private"),
			"account_alias":                eaN(30.0),
			"admin":                        eaB(false),
			"administratoraccess":          eaS("Deny"),
			"assume_role_policy":           eaS("roles/viewer"),
			"aws_iam_account_alias":        eaN(30.0),
			"description":                  eaS("private"),
			"empty":                        eaS("private"),
			"force_destroy":                eaS("private"),
			"force_detach_policies":        eaS("private"),
			"hard_expiry":                  eaS("private"),
			"managed_policy_arns":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"max_password_age":             eaS("P@ssw0rd!2024Strong"),
			"minimum_password_length":      eaS("P@ssw0rd!2024Strong"),
			"name":                         eaS("app"),
			"password_reset_required":      eaS("P@ssw0rd!2024Strong"),
			"password_reuse_prevention":    eaS("P@ssw0rd!2024Strong"),
			"permissions_boundary":         eaS("private"),
			"pgp_key":                      eaS("P@ssw0rd!2024Strong"),
			"policy":                       eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"policy_arn":                   eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"poweruseraccess":              eaS("Deny"),
			"prod":                         eaS("private"),
			"readonlyaccess":               eaS("Deny"),
			"require_lowercase_characters": eaB(true),
			"require_numbers":              eaB(true),
			"require_symbols":              eaB(true),
			"require_uppercase_characters": eaB(true),
			"status":                       eaS("private"),
			"tags":                         eaS("1.2.3"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-653: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{
		"Action":                       eaU(),
		"Active":                       eaU(),
		"Allow":                        eaU(),
		"Condition":                    eaU(),
		"Effect":                       eaU(),
		"NotAction":                    eaU(),
		"NotResource":                  eaU(),
		"Resource":                     eaU(),
		"Sid":                          eaU(),
		"account_alias":                eaU(),
		"admin":                        eaU(),
		"administratoraccess":          eaU(),
		"assume_role_policy":           eaU(),
		"aws_iam_account_alias":        eaU(),
		"bucket":                       eaU(),
		"description":                  eaU(),
		"empty":                        eaU(),
		"false":                        eaU(),
		"force_destroy":                eaU(),
		"force_detach_policies":        eaU(),
		"hard_expiry":                  eaU(),
		"managed_policy_arns":          eaU(),
		"max_password_age":             eaU(),
		"minimum_password_length":      eaU(),
		"name":                         eaU(),
		"password_reset_required":      eaU(),
		"password_reuse_prevention":    eaU(),
		"permissions_boundary":         eaU(),
		"pgp_key":                      eaU(),
		"policy":                       eaU(),
		"policy_arn":                   eaU(),
		"poweruseraccess":              eaU(),
		"prod":                         eaU(),
		"readonlyaccess":               eaU(),
		"require_lowercase_characters": eaU(),
		"require_numbers":              eaU(),
		"require_symbols":              eaU(),
		"require_uppercase_characters": eaU(),
		"rule":                         eaU(),
		"status":                       eaU(),
		"strings":                      eaU(),
		"tags":                         eaU(),
		"target_bucket":                eaU(),
		"true":                         eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-653: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_654(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-654")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-654: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-654: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-654: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{
			"Action":                       eaL(eaS("s3:GetObject")),
			"Active":                       eaS("private"),
			"Allow":                        eaS("private"),
			"Condition":                    eaS("private"),
			"Effect":                       eaS("Deny"),
			"NotAction":                    eaL(eaS("s3:GetObject")),
			"NotResource":                  eaL(eaS("arn:aws:s3:::mybucket/*")),
			"Resource":                     eaL(eaS("arn:aws:s3:::mybucket/*")),
			"Sid":                          eaS("private"),
			"account_alias":                eaN(30.0),
			"admin":                        eaB(false),
			"administratoraccess":          eaS("Deny"),
			"assume_role_policy":           eaS("roles/viewer"),
			"aws_iam_account_alias":        eaN(30.0),
			"description":                  eaS("private"),
			"empty":                        eaS("private"),
			"force_destroy":                eaS("private"),
			"force_detach_policies":        eaS("private"),
			"hard_expiry":                  eaS("private"),
			"managed_policy_arns":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"max_password_age":             eaS("P@ssw0rd!2024Strong"),
			"minimum_password_length":      eaS("P@ssw0rd!2024Strong"),
			"name":                         eaS("app"),
			"password_reset_required":      eaS("P@ssw0rd!2024Strong"),
			"password_reuse_prevention":    eaS("P@ssw0rd!2024Strong"),
			"permissions_boundary":         eaS("private"),
			"pgp_key":                      eaS("P@ssw0rd!2024Strong"),
			"policy":                       eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"policy_arn":                   eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"poweruseraccess":              eaS("Deny"),
			"prod":                         eaS("private"),
			"readonlyaccess":               eaS("Deny"),
			"require_lowercase_characters": eaB(true),
			"require_numbers":              eaB(true),
			"require_symbols":              eaB(true),
			"require_uppercase_characters": eaB(true),
			"status":                       eaS("private"),
			"tags":                         eaS("1.2.3"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-654: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_iam_account_password_policy", "probe", map[string]ir.Value{
		"Action":                       eaU(),
		"Active":                       eaU(),
		"Allow":                        eaU(),
		"Condition":                    eaU(),
		"Effect":                       eaU(),
		"NotAction":                    eaU(),
		"NotResource":                  eaU(),
		"Resource":                     eaU(),
		"Sid":                          eaU(),
		"account_alias":                eaU(),
		"admin":                        eaU(),
		"administratoraccess":          eaU(),
		"assume_role_policy":           eaU(),
		"aws_iam_account_alias":        eaU(),
		"bucket":                       eaU(),
		"description":                  eaU(),
		"empty":                        eaU(),
		"false":                        eaU(),
		"force_destroy":                eaU(),
		"force_detach_policies":        eaU(),
		"hard_expiry":                  eaU(),
		"managed_policy_arns":          eaU(),
		"max_password_age":             eaU(),
		"minimum_password_length":      eaU(),
		"name":                         eaU(),
		"password_reset_required":      eaU(),
		"password_reuse_prevention":    eaU(),
		"permissions_boundary":         eaU(),
		"pgp_key":                      eaU(),
		"policy":                       eaU(),
		"policy_arn":                   eaU(),
		"poweruseraccess":              eaU(),
		"prod":                         eaU(),
		"readonlyaccess":               eaU(),
		"require_lowercase_characters": eaU(),
		"require_numbers":              eaU(),
		"require_symbols":              eaU(),
		"require_uppercase_characters": eaU(),
		"rule":                         eaU(),
		"status":                       eaU(),
		"strings":                      eaU(),
		"tags":                         eaU(),
		"target_bucket":                eaU(),
		"true":                         eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-654: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_682(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-682")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_launch_template", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-682: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-682: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-682: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_launch_template", "probe", map[string]ir.Value{
			"EC2":                         eaS("public"),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(false),
			"cpu_credits":                 eaS("public"),
			"credit_specification":        eaS("public"),
			"delete_on_termination":       eaN(0.0),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaS("public"),
			"ebs_optimized":               eaS("public"),
			"enabled":                     eaB(false),
			"enclave_options":             eaS("public"),
			"encrypted":                   eaB(false),
			"get_password_data":           eaS("password123"),
			"health_check_type":           eaS("String"),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaS("public"),
			"instance_metadata_tags":      eaS("latest"),
			"max_size":                    eaN(0.0),
			"metadata_options":            eaS("public"),
			"min_size":                    eaN(0.0),
			"root_block_device":           eaB(false),
			"source_dest_check":           eaB(false),
			"unlimited":                   eaN(1.0),
			"update_default_version":      eaS(">= 1.0"),
			"user_data":                   eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64":            eaS("curl https://example.com/install.sh | sh"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-682: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_launch_template", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-682: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_683(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-683")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-683: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-683: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-683: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{
			"EC2":                         eaS("public"),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(false),
			"cpu_credits":                 eaS("public"),
			"credit_specification":        eaS("public"),
			"delete_on_termination":       eaN(0.0),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaS("public"),
			"ebs_optimized":               eaS("public"),
			"enabled":                     eaB(false),
			"enclave_options":             eaS("public"),
			"encrypted":                   eaB(false),
			"get_password_data":           eaS("password123"),
			"health_check_type":           eaS("String"),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaS("public"),
			"instance_metadata_tags":      eaS("latest"),
			"max_size":                    eaN(0.0),
			"metadata_options":            eaS("public"),
			"min_size":                    eaN(0.0),
			"root_block_device":           eaB(false),
			"source_dest_check":           eaB(false),
			"unlimited":                   eaN(1.0),
			"update_default_version":      eaS(">= 1.0"),
			"user_data":                   eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64":            eaS("curl https://example.com/install.sh | sh"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-683: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_instance", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-683: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_685(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-685")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{
			"EC2":                         eaB(true),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(true),
			"cpu_credits":                 eaB(true),
			"credit_specification":        eaB(true),
			"delete_on_termination":       eaB(true),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaB(true),
			"ebs_optimized":               eaB(true),
			"enabled":                     eaB(true),
			"enclave_options":             eaB(true),
			"encrypted":                   eaB(true),
			"get_password_data":           eaB(true),
			"health_check_type":           eaB(true),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaB(true),
			"instance_metadata_tags":      eaB(true),
			"max_size":                    eaB(true),
			"metadata_options":            eaB(true),
			"min_size":                    eaB(true),
			"root_block_device":           eaB(true),
			"source_dest_check":           eaB(true),
			"unlimited":                   eaB(true),
			"update_default_version":      eaB(true),
			"user_data":                   eaB(true),
			"user_data_base64":            eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-685: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-685: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-685: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-685: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_instance", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-685: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_686(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-686")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{
			"EC2":                         eaS("AKIAIOSFODNN7EXAMPLE"),
			"associate_public_ip_address": eaS("AKIAIOSFODNN7EXAMPLE"),
			"block_device_mappings":       eaS("AKIAIOSFODNN7EXAMPLE"),
			"cpu_credits":                 eaS("AKIAIOSFODNN7EXAMPLE"),
			"credit_specification":        eaS("AKIAIOSFODNN7EXAMPLE"),
			"delete_on_termination":       eaS("AKIAIOSFODNN7EXAMPLE"),
			"disable_api_termination":     eaS("AKIAIOSFODNN7EXAMPLE"),
			"ebs":                         eaS("AKIAIOSFODNN7EXAMPLE"),
			"ebs_optimized":               eaS("AKIAIOSFODNN7EXAMPLE"),
			"enabled":                     eaS("AKIAIOSFODNN7EXAMPLE"),
			"enclave_options":             eaS("AKIAIOSFODNN7EXAMPLE"),
			"encrypted":                   eaS("AKIAIOSFODNN7EXAMPLE"),
			"get_password_data":           eaS("AKIAIOSFODNN7EXAMPLE"),
			"health_check_type":           eaS("AKIAIOSFODNN7EXAMPLE"),
			"http_put_response_hop_limit": eaS("AKIAIOSFODNN7EXAMPLE"),
			"iam_instance_profile":        eaS("AKIAIOSFODNN7EXAMPLE"),
			"instance_metadata_tags":      eaS("AKIAIOSFODNN7EXAMPLE"),
			"max_size":                    eaS("AKIAIOSFODNN7EXAMPLE"),
			"metadata_options":            eaS("AKIAIOSFODNN7EXAMPLE"),
			"min_size":                    eaS("AKIAIOSFODNN7EXAMPLE"),
			"root_block_device":           eaS("AKIAIOSFODNN7EXAMPLE"),
			"source_dest_check":           eaS("AKIAIOSFODNN7EXAMPLE"),
			"unlimited":                   eaS("AKIAIOSFODNN7EXAMPLE"),
			"update_default_version":      eaS("AKIAIOSFODNN7EXAMPLE"),
			"user_data":                   eaS("AKIAIOSFODNN7EXAMPLE"),
			"user_data_base64":            eaS("AKIAIOSFODNN7EXAMPLE"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-686: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-686: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-686: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-686: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_instance", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-686: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_688(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-688")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_network_interface", "probe", map[string]ir.Value{
			"EC2":                         eaS("public"),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(false),
			"cpu_credits":                 eaS("public"),
			"credit_specification":        eaS("public"),
			"delete_on_termination":       eaN(0.0),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaS("public"),
			"ebs_optimized":               eaS("public"),
			"enabled":                     eaB(false),
			"enclave_options":             eaS("public"),
			"encrypted":                   eaB(false),
			"get_password_data":           eaS("password123"),
			"health_check_type":           eaS("String"),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaS("public"),
			"instance_metadata_tags":      eaS("latest"),
			"max_size":                    eaN(0.0),
			"metadata_options":            eaS("public"),
			"min_size":                    eaN(0.0),
			"root_block_device":           eaB(false),
			"source_dest_check":           eaB(false),
			"unlimited":                   eaN(1.0),
			"update_default_version":      eaS(">= 1.0"),
			"user_data":                   eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64":            eaS("curl https://example.com/install.sh | sh"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-688: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-688: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-688: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_network_interface", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-688: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_network_interface", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-688: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_689(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-689")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{
			"EC2":                         eaS("public"),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(false),
			"cpu_credits":                 eaS("public"),
			"credit_specification":        eaS("public"),
			"delete_on_termination":       eaN(0.0),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaS("public"),
			"ebs_optimized":               eaS("public"),
			"enabled":                     eaB(false),
			"enclave_options":             eaS("public"),
			"encrypted":                   eaB(false),
			"get_password_data":           eaS("password123"),
			"health_check_type":           eaS("String"),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaS("public"),
			"instance_metadata_tags":      eaS("latest"),
			"max_size":                    eaN(0.0),
			"metadata_options":            eaS("public"),
			"min_size":                    eaN(0.0),
			"root_block_device":           eaB(false),
			"source_dest_check":           eaB(false),
			"unlimited":                   eaN(1.0),
			"update_default_version":      eaS(">= 1.0"),
			"user_data":                   eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64":            eaS("curl https://example.com/install.sh | sh"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-689: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-689: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-689: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-689: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_instance", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-689: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_691(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-691")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_launch_template", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-691: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-691: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-691: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_launch_template", "probe", map[string]ir.Value{
			"EC2":                         eaS("public"),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(false),
			"cpu_credits":                 eaS("public"),
			"credit_specification":        eaS("public"),
			"delete_on_termination":       eaN(0.0),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaS("public"),
			"ebs_optimized":               eaS("public"),
			"enabled":                     eaB(false),
			"enclave_options":             eaS("public"),
			"encrypted":                   eaB(false),
			"get_password_data":           eaS("password123"),
			"health_check_type":           eaS("String"),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaS("public"),
			"instance_metadata_tags":      eaS("latest"),
			"max_size":                    eaN(0.0),
			"metadata_options":            eaS("public"),
			"min_size":                    eaN(0.0),
			"root_block_device":           eaB(false),
			"source_dest_check":           eaB(false),
			"unlimited":                   eaN(1.0),
			"update_default_version":      eaS(">= 1.0"),
			"user_data":                   eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64":            eaS("curl https://example.com/install.sh | sh"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-691: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_launch_template", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-691: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_694(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-694")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_ami_copy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-694: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-694: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-694: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_ami_copy", "probe", map[string]ir.Value{
			"EC2":                         eaS("private"),
			"associate_public_ip_address": eaB(false),
			"block_device_mappings":       eaB(true),
			"cpu_credits":                 eaS("private"),
			"credit_specification":        eaS("private"),
			"delete_on_termination":       eaN(30.0),
			"disable_api_termination":     eaB(false),
			"ebs":                         eaS("private"),
			"ebs_optimized":               eaS("private"),
			"enabled":                     eaB(true),
			"enclave_options":             eaS("private"),
			"encrypted":                   eaB(true),
			"get_password_data":           eaS("P@ssw0rd!2024Strong"),
			"health_check_type":           eaS("SecureString"),
			"http_put_response_hop_limit": eaB(false),
			"iam_instance_profile":        eaS("private"),
			"instance_metadata_tags":      eaS("1.2.3"),
			"max_size":                    eaN(30.0),
			"metadata_options":            eaS("private"),
			"min_size":                    eaN(30.0),
			"root_block_device":           eaB(true),
			"source_dest_check":           eaB(true),
			"unlimited":                   eaN(365.0),
			"update_default_version":      eaS("~> 5.0"),
			"user_data":                   eaS("#!/bin/bash\necho hello"),
			"user_data_base64":            eaS("#!/bin/bash\necho hello"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-694: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_ami_copy", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-694: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_695(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-695")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_ebs_snapshot_copy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-695: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-695: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-695: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_ebs_snapshot_copy", "probe", map[string]ir.Value{
			"EC2":                         eaS("private"),
			"associate_public_ip_address": eaB(false),
			"block_device_mappings":       eaB(true),
			"cpu_credits":                 eaS("private"),
			"credit_specification":        eaS("private"),
			"delete_on_termination":       eaN(30.0),
			"disable_api_termination":     eaB(false),
			"ebs":                         eaS("private"),
			"ebs_optimized":               eaS("private"),
			"enabled":                     eaB(true),
			"enclave_options":             eaS("private"),
			"encrypted":                   eaB(true),
			"get_password_data":           eaS("P@ssw0rd!2024Strong"),
			"health_check_type":           eaS("SecureString"),
			"http_put_response_hop_limit": eaB(false),
			"iam_instance_profile":        eaS("private"),
			"instance_metadata_tags":      eaS("1.2.3"),
			"max_size":                    eaN(30.0),
			"metadata_options":            eaS("private"),
			"min_size":                    eaN(30.0),
			"root_block_device":           eaB(true),
			"source_dest_check":           eaB(true),
			"unlimited":                   eaN(365.0),
			"update_default_version":      eaS("~> 5.0"),
			"user_data":                   eaS("#!/bin/bash\necho hello"),
			"user_data_base64":            eaS("#!/bin/bash\necho hello"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-695: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_ebs_snapshot_copy", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-695: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_696(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-696")
	// Positive: explicit root_block_device with encrypted = false.
	// (Absent block is NOT a positive: encryption then follows the
	// AMI snapshot + account EBS default.)
	pos := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{
			"root_block_device": eaL(eaM("encrypted", eaB(false))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-696: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-696: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-696: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{
			"EC2":                         eaS("public"),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(false),
			"cpu_credits":                 eaS("public"),
			"credit_specification":        eaS("public"),
			"delete_on_termination":       eaN(0.0),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaS("public"),
			"ebs_optimized":               eaS("public"),
			"enabled":                     eaB(false),
			"enclave_options":             eaS("public"),
			"encrypted":                   eaB(false),
			"get_password_data":           eaS("password123"),
			"health_check_type":           eaS("String"),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaS("public"),
			"instance_metadata_tags":      eaS("latest"),
			"max_size":                    eaN(0.0),
			"metadata_options":            eaS("public"),
			"min_size":                    eaN(0.0),
			"root_block_device":           eaB(false),
			"rule":                        eaS("public"),
			"source_dest_check":           eaB(false),
			"unlimited":                   eaN(1.0),
			"update_default_version":      eaS(">= 1.0"),
			"user_data":                   eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64":            eaS("curl https://example.com/install.sh | sh"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-696: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_instance", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-696: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_697(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-697")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_launch_template", "probe", map[string]ir.Value{
			"block_device_mappings": eaL(eaM("ebs", eaL(eaM("EC2", eaB(false), "associate_public_ip_address", eaB(false), "block_device_mappings", eaB(false), "cpu_credits", eaB(false), "credit_specification", eaB(false), "delete_on_termination", eaB(false), "disable_api_termination", eaB(false), "ebs", eaB(false), "ebs_optimized", eaB(false), "enabled", eaB(false), "enclave_options", eaB(false), "encrypted", eaB(false), "get_password_data", eaB(false), "health_check_type", eaB(false), "http_put_response_hop_limit", eaB(false), "iam_instance_profile", eaB(false), "instance_metadata_tags", eaB(false), "max_size", eaB(false), "metadata_options", eaB(false), "min_size", eaB(false), "root_block_device", eaB(false), "rule", eaB(false), "source_dest_check", eaB(false), "unlimited", eaB(false), "update_default_version", eaB(false), "user_data", eaB(false), "user_data_base64", eaB(false))))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-697: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-697: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-697: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_launch_template", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-697: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_launch_template", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-697: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_698(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-698")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_autoscaling_group", "probe", map[string]ir.Value{
			"EC2":                         eaS("public"),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(false),
			"cpu_credits":                 eaS("public"),
			"credit_specification":        eaS("public"),
			"delete_on_termination":       eaN(0.0),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaS("public"),
			"ebs_optimized":               eaS("public"),
			"enabled":                     eaB(false),
			"enclave_options":             eaS("public"),
			"encrypted":                   eaB(false),
			"get_password_data":           eaS("password123"),
			"health_check_type":           eaS("String"),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaS("public"),
			"instance_metadata_tags":      eaS("latest"),
			"max_size":                    eaN(0.0),
			"metadata_options":            eaS("public"),
			"min_size":                    eaN(0.0),
			"root_block_device":           eaB(false),
			"source_dest_check":           eaB(false),
			"unlimited":                   eaN(1.0),
			"update_default_version":      eaS(">= 1.0"),
			"user_data":                   eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64":            eaS("curl https://example.com/install.sh | sh"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-698: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-698: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-698: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_autoscaling_group", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-698: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_autoscaling_group", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-698: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_699(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-699")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-699: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-699: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-699: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_instance", "probe", map[string]ir.Value{
			"EC2":                         eaS("public"),
			"associate_public_ip_address": eaB(true),
			"block_device_mappings":       eaB(false),
			"cpu_credits":                 eaS("public"),
			"credit_specification":        eaS("public"),
			"delete_on_termination":       eaN(0.0),
			"disable_api_termination":     eaB(true),
			"ebs":                         eaS("public"),
			"ebs_optimized":               eaS("public"),
			"enabled":                     eaB(false),
			"enclave_options":             eaS("public"),
			"encrypted":                   eaB(false),
			"get_password_data":           eaS("password123"),
			"health_check_type":           eaS("String"),
			"http_put_response_hop_limit": eaB(true),
			"iam_instance_profile":        eaS("public"),
			"instance_metadata_tags":      eaS("latest"),
			"max_size":                    eaN(0.0),
			"metadata_options":            eaS("public"),
			"min_size":                    eaN(0.0),
			"root_block_device":           eaB(false),
			"rule":                        eaS("public"),
			"source_dest_check":           eaB(false),
			"unlimited":                   eaN(1.0),
			"update_default_version":      eaS(">= 1.0"),
			"user_data":                   eaS("curl https://example.com/install.sh | sh"),
			"user_data_base64":            eaS("curl https://example.com/install.sh | sh"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-699: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_instance", "probe", map[string]ir.Value{
		"EC2":                         eaU(),
		"associate_public_ip_address": eaU(),
		"block_device_mappings":       eaU(),
		"bucket":                      eaU(),
		"cpu_credits":                 eaU(),
		"credit_specification":        eaU(),
		"delete_on_termination":       eaU(),
		"disable_api_termination":     eaU(),
		"ebs":                         eaU(),
		"ebs_optimized":               eaU(),
		"enabled":                     eaU(),
		"enclave_options":             eaU(),
		"encrypted":                   eaU(),
		"false":                       eaU(),
		"get_password_data":           eaU(),
		"health_check_type":           eaU(),
		"http_put_response_hop_limit": eaU(),
		"iam_instance_profile":        eaU(),
		"instance_metadata_tags":      eaU(),
		"max_size":                    eaU(),
		"metadata_options":            eaU(),
		"min_size":                    eaU(),
		"root_block_device":           eaU(),
		"rule":                        eaU(),
		"source_dest_check":           eaU(),
		"strings":                     eaU(),
		"target_bucket":               eaU(),
		"true":                        eaU(),
		"unlimited":                   eaU(),
		"update_default_version":      eaU(),
		"user_data":                   eaU(),
		"user_data_base64":            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-699: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_700(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-700")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_rds_cluster", "probe", map[string]ir.Value{
			"performance_insights_enabled": eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-700: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-700: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-700: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_rds_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-700: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_rds_cluster", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-700: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_703(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-703")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_rds_cluster", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaB(true),
			"automated_snapshot_retention_period": eaB(true),
			"automatic_failover_enabled":          eaB(true),
			"backup_retention_period":             eaB(true),
			"copy_tags_to_snapshot":               eaB(true),
			"db_cluster_parameter_group_name":     eaB(true),
			"default":                             eaB(true),
			"manage_master_user_password":         eaB(true),
			"name":                                eaB(true),
			"num_cache_clusters":                  eaB(true),
			"option_group_name":                   eaB(true),
			"parameter":                           eaB(true),
			"password":                            eaB(true),
			"performance_insights_enabled":        eaB(true),
			"performance_insights_kms_key_id":     eaB(true),
			"shared_accounts":                     eaB(true),
			"skip_final_snapshot":                 eaB(true),
			"snapshot_retention_limit":            eaB(true),
			"subnet_ids":                          eaB(true),
			"value":                               eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-703: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-703: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-703: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_rds_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-703: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_rds_cluster", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-703: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_704(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-704")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_rds_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-704: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-704: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-704: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_rds_cluster", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaS(">= 1.0"),
			"automated_snapshot_retention_period": eaN(1.0),
			"automatic_failover_enabled":          eaB(false),
			"backup_retention_period":             eaB(false),
			"copy_tags_to_snapshot":               eaS("latest"),
			"db_cluster_parameter_group_name":     eaS("my_password"),
			"default":                             eaS("public"),
			"manage_master_user_password":         eaS("password123"),
			"name":                                eaS("my_password"),
			"num_cache_clusters":                  eaS("public"),
			"option_group_name":                   eaS("my_password"),
			"parameter":                           eaS("public"),
			"password":                            eaS("password123"),
			"performance_insights_enabled":        eaB(false),
			"performance_insights_kms_key_id":     eaS("password123"),
			"shared_accounts":                     eaN(0.0),
			"skip_final_snapshot":                 eaS("public"),
			"snapshot_retention_limit":            eaN(1.0),
			"subnet_ids":                          eaS("public"),
			"value":                               eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-704: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_rds_cluster", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-704: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_705(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-705")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_db_cluster_snapshot", "probe", map[string]ir.Value{
			"shared_accounts": eaL(eaM("allow_version_upgrade", eaS(">= 1.0"), "automated_snapshot_retention_period", eaN(1.0), "automatic_failover_enabled", eaB(false), "backup_retention_period", eaB(false), "copy_tags_to_snapshot", eaS("latest"), "db_cluster_parameter_group_name", eaS("my_password"), "default", eaS("public"), "manage_master_user_password", eaS("password123"), "name", eaS("my_password"), "num_cache_clusters", eaS("public"), "option_group_name", eaS("my_password"), "parameter", eaS("public"), "password", eaS("password123"), "performance_insights_enabled", eaB(false), "performance_insights_kms_key_id", eaS("password123"), "shared_accounts", eaN(0.0), "skip_final_snapshot", eaS("public"), "snapshot_retention_limit", eaN(1.0), "subnet_ids", eaS("public"), "value", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-705: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-705: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-705: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_db_cluster_snapshot", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-705: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_db_cluster_snapshot", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-705: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_706(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-706")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_db_instance", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-706: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-706: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-706: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_db_instance", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaS(">= 1.0"),
			"automated_snapshot_retention_period": eaN(1.0),
			"automatic_failover_enabled":          eaB(false),
			"backup_retention_period":             eaB(false),
			"copy_tags_to_snapshot":               eaS("latest"),
			"db_cluster_parameter_group_name":     eaS("my_password"),
			"default":                             eaS("public"),
			"manage_master_user_password":         eaS("password123"),
			"name":                                eaS("my_password"),
			"num_cache_clusters":                  eaS("public"),
			"option_group_name":                   eaS("my_password"),
			"parameter":                           eaS("public"),
			"password":                            eaS("password123"),
			"performance_insights_enabled":        eaB(false),
			"performance_insights_kms_key_id":     eaS("password123"),
			"rule":                                eaS("public"),
			"shared_accounts":                     eaN(0.0),
			"skip_final_snapshot":                 eaS("public"),
			"snapshot_retention_limit":            eaN(1.0),
			"subnet_ids":                          eaS("public"),
			"value":                               eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-706: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_db_instance", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-706: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_707(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-707")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_db_subnet_group", "probe", map[string]ir.Value{
			"subnet_ids": eaL(eaM("allow_version_upgrade", eaS(">= 1.0"), "automated_snapshot_retention_period", eaN(1.0), "automatic_failover_enabled", eaB(false), "backup_retention_period", eaB(false), "copy_tags_to_snapshot", eaS("latest"), "db_cluster_parameter_group_name", eaS("my_password"), "default", eaS("public"), "manage_master_user_password", eaS("password123"), "name", eaS("my_password"), "num_cache_clusters", eaS("public"), "option_group_name", eaS("my_password"), "parameter", eaS("public"), "password", eaS("password123"), "performance_insights_enabled", eaB(false), "performance_insights_kms_key_id", eaS("password123"), "shared_accounts", eaN(0.0), "skip_final_snapshot", eaS("public"), "snapshot_retention_limit", eaN(1.0), "subnet_ids", eaS("public"), "value", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-707: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-707: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-707: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_db_subnet_group", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-707: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_db_subnet_group", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-707: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_708(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-708")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_rds_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-708: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-708: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-708: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_rds_cluster", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaS(">= 1.0"),
			"automated_snapshot_retention_period": eaN(1.0),
			"automatic_failover_enabled":          eaB(false),
			"backup_retention_period":             eaB(false),
			"copy_tags_to_snapshot":               eaS("latest"),
			"db_cluster_parameter_group_name":     eaS("my_password"),
			"default":                             eaS("public"),
			"manage_master_user_password":         eaS("password123"),
			"name":                                eaS("my_password"),
			"num_cache_clusters":                  eaS("public"),
			"option_group_name":                   eaS("my_password"),
			"parameter":                           eaS("public"),
			"password":                            eaS("password123"),
			"performance_insights_enabled":        eaB(false),
			"performance_insights_kms_key_id":     eaS("password123"),
			"rule":                                eaS("public"),
			"shared_accounts":                     eaN(0.0),
			"skip_final_snapshot":                 eaS("public"),
			"snapshot_retention_limit":            eaN(1.0),
			"subnet_ids":                          eaS("public"),
			"value":                               eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-708: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_rds_cluster", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-708: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_710(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-710")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_db_instance", "probe", map[string]ir.Value{
			"password": eaS("0.0.0.0/0"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-710: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-710: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-710: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_db_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-710: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_db_instance", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-710: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_711(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-711")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaB(false),
			"automated_snapshot_retention_period": eaB(false),
			"automatic_failover_enabled":          eaB(false),
			"backup_retention_period":             eaB(false),
			"copy_tags_to_snapshot":               eaB(false),
			"db_cluster_parameter_group_name":     eaB(false),
			"default":                             eaB(false),
			"manage_master_user_password":         eaB(false),
			"name":                                eaB(false),
			"num_cache_clusters":                  eaB(false),
			"option_group_name":                   eaB(false),
			"parameter":                           eaB(false),
			"password":                            eaB(false),
			"performance_insights_enabled":        eaB(false),
			"performance_insights_kms_key_id":     eaB(false),
			"shared_accounts":                     eaB(false),
			"skip_final_snapshot":                 eaB(false),
			"snapshot_retention_limit":            eaB(false),
			"subnet_ids":                          eaB(false),
			"value":                               eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-711: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-711: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-711: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-711: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-711: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_712(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-712")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaS(">= 1.0"),
			"automated_snapshot_retention_period": eaN(1.0),
			"automatic_failover_enabled":          eaB(false),
			"backup_retention_period":             eaB(false),
			"copy_tags_to_snapshot":               eaS("latest"),
			"db_cluster_parameter_group_name":     eaS("my_password"),
			"default":                             eaS("public"),
			"manage_master_user_password":         eaS("password123"),
			"name":                                eaS("my_password"),
			"num_cache_clusters":                  eaS("public"),
			"option_group_name":                   eaS("my_password"),
			"parameter":                           eaS("public"),
			"password":                            eaS("password123"),
			"performance_insights_enabled":        eaB(false),
			"performance_insights_kms_key_id":     eaS("password123"),
			"shared_accounts":                     eaN(0.0),
			"skip_final_snapshot":                 eaS("public"),
			"snapshot_retention_limit":            eaN(1.0),
			"subnet_ids":                          eaS("public"),
			"value":                               eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-712: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-712: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-712: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-712: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-712: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_713(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-713")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-713: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-713: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-713: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaS(">= 1.0"),
			"automated_snapshot_retention_period": eaN(1.0),
			"automatic_failover_enabled":          eaB(false),
			"backup_retention_period":             eaB(false),
			"copy_tags_to_snapshot":               eaS("latest"),
			"db_cluster_parameter_group_name":     eaS("my_password"),
			"default":                             eaS("public"),
			"manage_master_user_password":         eaS("password123"),
			"name":                                eaS("my_password"),
			"num_cache_clusters":                  eaS("public"),
			"option_group_name":                   eaS("my_password"),
			"parameter":                           eaS("public"),
			"password":                            eaS("password123"),
			"performance_insights_enabled":        eaB(false),
			"performance_insights_kms_key_id":     eaS("password123"),
			"shared_accounts":                     eaN(0.0),
			"skip_final_snapshot":                 eaS("public"),
			"snapshot_retention_limit":            eaN(1.0),
			"subnet_ids":                          eaS("public"),
			"value":                               eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-713: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_redshift_cluster", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-713: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_714(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-714")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_elasticache_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-714: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-714: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-714: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_elasticache_cluster", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaS(">= 1.0"),
			"automated_snapshot_retention_period": eaN(1.0),
			"automatic_failover_enabled":          eaB(false),
			"backup_retention_period":             eaB(false),
			"copy_tags_to_snapshot":               eaS("latest"),
			"db_cluster_parameter_group_name":     eaS("my_password"),
			"default":                             eaS("public"),
			"manage_master_user_password":         eaS("password123"),
			"name":                                eaS("my_password"),
			"num_cache_clusters":                  eaS("public"),
			"option_group_name":                   eaS("my_password"),
			"parameter":                           eaS("public"),
			"password":                            eaS("password123"),
			"performance_insights_enabled":        eaB(false),
			"performance_insights_kms_key_id":     eaS("password123"),
			"shared_accounts":                     eaN(0.0),
			"skip_final_snapshot":                 eaS("public"),
			"snapshot_retention_limit":            eaN(1.0),
			"subnet_ids":                          eaS("public"),
			"value":                               eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-714: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_elasticache_cluster", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-714: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_716(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-716")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_elasticache_replication_group", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-716: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-716: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-716: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_elasticache_replication_group", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaS("~> 5.0"),
			"automated_snapshot_retention_period": eaN(365.0),
			"automatic_failover_enabled":          eaB(true),
			"backup_retention_period":             eaB(true),
			"copy_tags_to_snapshot":               eaS("1.2.3"),
			"db_cluster_parameter_group_name":     eaS("app"),
			"default":                             eaS("private"),
			"manage_master_user_password":         eaS("P@ssw0rd!2024Strong"),
			"name":                                eaS("app"),
			"num_cache_clusters":                  eaS("private"),
			"option_group_name":                   eaS("app"),
			"parameter":                           eaS("private"),
			"password":                            eaS("P@ssw0rd!2024Strong"),
			"performance_insights_enabled":        eaB(true),
			"performance_insights_kms_key_id":     eaS("P@ssw0rd!2024Strong"),
			"shared_accounts":                     eaN(30.0),
			"skip_final_snapshot":                 eaS("private"),
			"snapshot_retention_limit":            eaN(365.0),
			"subnet_ids":                          eaS("private"),
			"value":                               eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-716: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_elasticache_replication_group", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-716: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_717(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-717")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_elasticache_replication_group", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-717: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-717: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-717: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_elasticache_replication_group", "probe", map[string]ir.Value{
			"allow_version_upgrade":               eaS(">= 1.0"),
			"automated_snapshot_retention_period": eaN(1.0),
			"automatic_failover_enabled":          eaB(false),
			"backup_retention_period":             eaB(false),
			"copy_tags_to_snapshot":               eaS("latest"),
			"db_cluster_parameter_group_name":     eaS("my_password"),
			"default":                             eaS("public"),
			"manage_master_user_password":         eaS("password123"),
			"name":                                eaS("my_password"),
			"num_cache_clusters":                  eaS("public"),
			"option_group_name":                   eaS("my_password"),
			"parameter":                           eaS("public"),
			"password":                            eaS("password123"),
			"performance_insights_enabled":        eaB(false),
			"performance_insights_kms_key_id":     eaS("password123"),
			"shared_accounts":                     eaN(0.0),
			"skip_final_snapshot":                 eaS("public"),
			"snapshot_retention_limit":            eaN(1.0),
			"subnet_ids":                          eaS("public"),
			"value":                               eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-717: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_elasticache_replication_group", "probe", map[string]ir.Value{
		"allow_version_upgrade":               eaU(),
		"automated_snapshot_retention_period": eaU(),
		"automatic_failover_enabled":          eaU(),
		"backup_retention_period":             eaU(),
		"bucket":                              eaU(),
		"copy_tags_to_snapshot":               eaU(),
		"db_cluster_parameter_group_name":     eaU(),
		"default":                             eaU(),
		"false":                               eaU(),
		"manage_master_user_password":         eaU(),
		"name":                                eaU(),
		"num_cache_clusters":                  eaU(),
		"option_group_name":                   eaU(),
		"parameter":                           eaU(),
		"password":                            eaU(),
		"performance_insights_enabled":        eaU(),
		"performance_insights_kms_key_id":     eaU(),
		"rule":                                eaU(),
		"shared_accounts":                     eaU(),
		"skip_final_snapshot":                 eaU(),
		"snapshot_retention_limit":            eaU(),
		"strings":                             eaU(),
		"subnet_ids":                          eaU(),
		"target_bucket":                       eaU(),
		"true":                                eaU(),
		"value":                               eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-717: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_804(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-804")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_sagemaker_endpoint_configuration", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-804: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-804: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-804: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_sagemaker_endpoint_configuration", "probe", map[string]ir.Value{
			"Enabled":                         eaB(false),
			"PER_TOPIC_PER_BROKER":            eaS("public"),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaS("public"),
			"absent":                          eaS("public"),
			"advanced_security_options":       eaB(false),
			"app_network_access_type":         eaS("String"),
			"client_broker":                   eaS("public"),
			"configuration":                   eaS("public"),
			"container_properties":            eaS("public"),
			"content_policy_config":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"copy_tags_to_snapshot":           eaS("latest"),
			"data_capture_config":             eaS("public"),
			"direct_internet_access":          eaS("Allow"),
			"enabled":                         eaB(false),
			"encryption_configuration":        eaB(false),
			"encryption_info":                 eaB(false),
			"encryption_option":               eaB(false),
			"enforce_workgroup_configuration": eaB(false),
			"enhanced_monitoring":             eaB(false),
			"error_report_configuration":      eaS("3389"),
			"health_check":                    eaB(false),
			"kms_key_arn":                     eaS("password123"),
			"log_publishing_options":          eaB(false),
			"logging_configurations":          eaB(false),
			"number_of_broker_nodes":          eaS("public"),
			"path":                            eaS("public"),
			"privileged":                      eaB(true),
			"result_configuration":            eaS("public"),
			"retention_days":                  eaN(1.0),
			"root_access":                     eaS("Allow"),
			"rule":                            eaS("public"),
			"s3_configuration":                eaS("public"),
			"server_side_encryption":          eaB(false),
			"shard_level_metrics":             eaS("public"),
			"skip_final_snapshot":             eaS("public"),
			"text_data_delivery":              eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-804: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_sagemaker_endpoint_configuration", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-804: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_807(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-807")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_scheduler_schedule", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-807: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-807: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-807: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_scheduler_schedule", "probe", map[string]ir.Value{
			"Enabled":                         eaB(false),
			"PER_TOPIC_PER_BROKER":            eaS("public"),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaS("public"),
			"absent":                          eaS("public"),
			"advanced_security_options":       eaB(false),
			"app_network_access_type":         eaS("String"),
			"client_broker":                   eaS("public"),
			"configuration":                   eaS("public"),
			"container_properties":            eaS("public"),
			"content_policy_config":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"copy_tags_to_snapshot":           eaS("latest"),
			"data_capture_config":             eaS("public"),
			"direct_internet_access":          eaS("Allow"),
			"enabled":                         eaB(false),
			"encryption_configuration":        eaB(false),
			"encryption_info":                 eaB(false),
			"encryption_option":               eaB(false),
			"enforce_workgroup_configuration": eaB(false),
			"enhanced_monitoring":             eaB(false),
			"error_report_configuration":      eaS("3389"),
			"health_check":                    eaB(false),
			"kms_key_arn":                     eaS("password123"),
			"log_publishing_options":          eaB(false),
			"logging_configurations":          eaB(false),
			"number_of_broker_nodes":          eaS("public"),
			"path":                            eaS("public"),
			"privileged":                      eaB(true),
			"result_configuration":            eaS("public"),
			"retention_days":                  eaN(1.0),
			"root_access":                     eaS("Allow"),
			"rule":                            eaS("public"),
			"s3_configuration":                eaS("public"),
			"server_side_encryption":          eaB(false),
			"shard_level_metrics":             eaS("public"),
			"skip_final_snapshot":             eaS("public"),
			"text_data_delivery":              eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-807: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_scheduler_schedule", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-807: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_809(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-809")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_msk_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-809: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-809: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-809: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_msk_cluster", "probe", map[string]ir.Value{
			"Enabled":                         eaB(false),
			"PER_TOPIC_PER_BROKER":            eaS("public"),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaS("public"),
			"absent":                          eaS("public"),
			"advanced_security_options":       eaB(false),
			"app_network_access_type":         eaS("String"),
			"client_broker":                   eaS("public"),
			"configuration":                   eaS("public"),
			"container_properties":            eaS("public"),
			"content_policy_config":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"copy_tags_to_snapshot":           eaS("latest"),
			"data_capture_config":             eaS("public"),
			"direct_internet_access":          eaS("Allow"),
			"enabled":                         eaB(false),
			"encryption_configuration":        eaB(false),
			"encryption_info":                 eaB(false),
			"encryption_option":               eaB(false),
			"enforce_workgroup_configuration": eaB(false),
			"enhanced_monitoring":             eaB(false),
			"error_report_configuration":      eaS("3389"),
			"health_check":                    eaB(false),
			"kms_key_arn":                     eaS("password123"),
			"log_publishing_options":          eaB(false),
			"logging_configurations":          eaB(false),
			"number_of_broker_nodes":          eaS("public"),
			"path":                            eaS("public"),
			"privileged":                      eaB(true),
			"result_configuration":            eaS("public"),
			"retention_days":                  eaN(1.0),
			"root_access":                     eaS("Allow"),
			"rule":                            eaS("public"),
			"s3_configuration":                eaS("public"),
			"server_side_encryption":          eaB(false),
			"shard_level_metrics":             eaS("public"),
			"skip_final_snapshot":             eaS("public"),
			"text_data_delivery":              eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-809: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_msk_cluster", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-809: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_810(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-810")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_msk_cluster", "probe", map[string]ir.Value{
			"Enabled":                         eaN(0.0),
			"PER_TOPIC_PER_BROKER":            eaN(0.0),
			"PLAINTEXT":                       eaN(0.0),
			"PublicInternetOnly":              eaN(0.0),
			"SSE_KMS":                         eaN(0.0),
			"absent":                          eaN(0.0),
			"advanced_security_options":       eaN(0.0),
			"app_network_access_type":         eaN(0.0),
			"client_broker":                   eaN(0.0),
			"configuration":                   eaN(0.0),
			"container_properties":            eaN(0.0),
			"content_policy_config":           eaN(0.0),
			"copy_tags_to_snapshot":           eaN(0.0),
			"data_capture_config":             eaN(0.0),
			"direct_internet_access":          eaN(0.0),
			"enabled":                         eaN(0.0),
			"encryption_configuration":        eaN(0.0),
			"encryption_info":                 eaN(0.0),
			"encryption_option":               eaN(0.0),
			"enforce_workgroup_configuration": eaN(0.0),
			"enhanced_monitoring":             eaN(0.0),
			"error_report_configuration":      eaN(0.0),
			"health_check":                    eaN(0.0),
			"kms_key_arn":                     eaN(0.0),
			"log_publishing_options":          eaN(0.0),
			"logging_configurations":          eaN(0.0),
			"number_of_broker_nodes":          eaN(0.0),
			"path":                            eaN(0.0),
			"privileged":                      eaN(0.0),
			"result_configuration":            eaN(0.0),
			"retention_days":                  eaN(0.0),
			"root_access":                     eaN(0.0),
			"s3_configuration":                eaN(0.0),
			"server_side_encryption":          eaN(0.0),
			"shard_level_metrics":             eaN(0.0),
			"skip_final_snapshot":             eaN(0.0),
			"text_data_delivery":              eaN(0.0),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-810: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-810: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-810: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_msk_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-810: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_msk_cluster", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-810: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_813(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-813")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_neptune_cluster", "probe", map[string]ir.Value{
			"Enabled":                         eaB(true),
			"PER_TOPIC_PER_BROKER":            eaB(true),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaB(true),
			"absent":                          eaB(true),
			"advanced_security_options":       eaB(true),
			"app_network_access_type":         eaB(true),
			"client_broker":                   eaB(true),
			"configuration":                   eaB(true),
			"container_properties":            eaB(true),
			"content_policy_config":           eaB(true),
			"copy_tags_to_snapshot":           eaB(true),
			"data_capture_config":             eaB(true),
			"direct_internet_access":          eaB(true),
			"enabled":                         eaB(true),
			"encryption_configuration":        eaB(true),
			"encryption_info":                 eaB(true),
			"encryption_option":               eaB(true),
			"enforce_workgroup_configuration": eaB(true),
			"enhanced_monitoring":             eaB(true),
			"error_report_configuration":      eaB(true),
			"health_check":                    eaB(true),
			"kms_key_arn":                     eaB(true),
			"log_publishing_options":          eaB(true),
			"logging_configurations":          eaB(true),
			"number_of_broker_nodes":          eaB(true),
			"path":                            eaB(true),
			"privileged":                      eaB(true),
			"result_configuration":            eaB(true),
			"retention_days":                  eaB(true),
			"root_access":                     eaB(true),
			"s3_configuration":                eaB(true),
			"server_side_encryption":          eaB(true),
			"shard_level_metrics":             eaB(true),
			"skip_final_snapshot":             eaB(true),
			"text_data_delivery":              eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-813: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-813: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-813: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_neptune_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-813: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_neptune_cluster", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-813: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_814(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-814")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_neptune_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-814: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-814: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-814: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_neptune_cluster", "probe", map[string]ir.Value{
			"Enabled":                         eaB(false),
			"PER_TOPIC_PER_BROKER":            eaS("public"),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaS("public"),
			"absent":                          eaS("public"),
			"advanced_security_options":       eaB(false),
			"app_network_access_type":         eaS("String"),
			"client_broker":                   eaS("public"),
			"configuration":                   eaS("public"),
			"container_properties":            eaS("public"),
			"content_policy_config":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"copy_tags_to_snapshot":           eaS("latest"),
			"data_capture_config":             eaS("public"),
			"direct_internet_access":          eaS("Allow"),
			"enabled":                         eaB(false),
			"encryption_configuration":        eaB(false),
			"encryption_info":                 eaB(false),
			"encryption_option":               eaB(false),
			"enforce_workgroup_configuration": eaB(false),
			"enhanced_monitoring":             eaB(false),
			"error_report_configuration":      eaS("3389"),
			"health_check":                    eaB(false),
			"kms_key_arn":                     eaS("password123"),
			"log_publishing_options":          eaB(false),
			"logging_configurations":          eaB(false),
			"number_of_broker_nodes":          eaS("public"),
			"path":                            eaS("public"),
			"privileged":                      eaB(true),
			"result_configuration":            eaS("public"),
			"retention_days":                  eaN(1.0),
			"root_access":                     eaS("Allow"),
			"s3_configuration":                eaS("public"),
			"server_side_encryption":          eaB(false),
			"shard_level_metrics":             eaS("public"),
			"skip_final_snapshot":             eaS("public"),
			"text_data_delivery":              eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-814: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_neptune_cluster", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-814: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_816(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-816")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_apprunner_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-816: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-816: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-816: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_apprunner_service", "probe", map[string]ir.Value{
			"Enabled":                         eaB(false),
			"PER_TOPIC_PER_BROKER":            eaS("public"),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaS("public"),
			"absent":                          eaS("public"),
			"advanced_security_options":       eaB(false),
			"app_network_access_type":         eaS("String"),
			"client_broker":                   eaS("public"),
			"configuration":                   eaS("public"),
			"container_properties":            eaS("public"),
			"content_policy_config":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"copy_tags_to_snapshot":           eaS("latest"),
			"data_capture_config":             eaS("public"),
			"direct_internet_access":          eaS("Allow"),
			"enabled":                         eaB(false),
			"encryption_configuration":        eaB(false),
			"encryption_info":                 eaB(false),
			"encryption_option":               eaB(false),
			"enforce_workgroup_configuration": eaB(false),
			"enhanced_monitoring":             eaB(false),
			"error_report_configuration":      eaS("3389"),
			"health_check":                    eaB(false),
			"kms_key_arn":                     eaS("password123"),
			"log_publishing_options":          eaB(false),
			"logging_configurations":          eaB(false),
			"number_of_broker_nodes":          eaS("public"),
			"path":                            eaS("public"),
			"privileged":                      eaB(true),
			"result_configuration":            eaS("public"),
			"retention_days":                  eaN(1.0),
			"root_access":                     eaS("Allow"),
			"rule":                            eaS("public"),
			"s3_configuration":                eaS("public"),
			"server_side_encryption":          eaB(false),
			"shard_level_metrics":             eaS("public"),
			"skip_final_snapshot":             eaS("public"),
			"text_data_delivery":              eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-816: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_apprunner_service", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-816: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_820(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-820")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_athena_workgroup", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-820: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-820: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-820: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_athena_workgroup", "probe", map[string]ir.Value{
			"Enabled":                         eaB(false),
			"PER_TOPIC_PER_BROKER":            eaS("public"),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaS("public"),
			"absent":                          eaS("public"),
			"advanced_security_options":       eaB(false),
			"app_network_access_type":         eaS("String"),
			"client_broker":                   eaS("public"),
			"configuration":                   eaS("public"),
			"container_properties":            eaS("public"),
			"content_policy_config":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"copy_tags_to_snapshot":           eaS("latest"),
			"data_capture_config":             eaS("public"),
			"direct_internet_access":          eaS("Allow"),
			"enabled":                         eaB(false),
			"encryption_configuration":        eaB(false),
			"encryption_info":                 eaB(false),
			"encryption_option":               eaB(false),
			"enforce_workgroup_configuration": eaB(false),
			"enhanced_monitoring":             eaB(false),
			"error_report_configuration":      eaS("3389"),
			"health_check":                    eaB(false),
			"kms_key_arn":                     eaS("password123"),
			"log_publishing_options":          eaB(false),
			"logging_configurations":          eaB(false),
			"number_of_broker_nodes":          eaS("public"),
			"path":                            eaS("public"),
			"privileged":                      eaB(true),
			"result_configuration":            eaS("public"),
			"retention_days":                  eaN(1.0),
			"root_access":                     eaS("Allow"),
			"rule":                            eaS("public"),
			"s3_configuration":                eaS("public"),
			"server_side_encryption":          eaB(false),
			"shard_level_metrics":             eaS("public"),
			"skip_final_snapshot":             eaS("public"),
			"text_data_delivery":              eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-820: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_athena_workgroup", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-820: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_821(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-821")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_athena_workgroup", "probe", map[string]ir.Value{
			"configuration": eaL(eaM("Enabled", eaB(false), "PER_TOPIC_PER_BROKER", eaS("public"), "PLAINTEXT", eaB(true), "PublicInternetOnly", eaB(true), "SSE_KMS", eaS("public"), "absent", eaS("public"), "advanced_security_options", eaB(false), "app_network_access_type", eaS("String"), "client_broker", eaS("public"), "configuration", eaS("public"), "container_properties", eaS("public"), "content_policy_config", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "copy_tags_to_snapshot", eaS("latest"), "data_capture_config", eaS("public"), "direct_internet_access", eaS("Allow"), "enabled", eaB(false), "encryption_configuration", eaB(false), "encryption_info", eaB(false), "encryption_option", eaB(false), "enforce_workgroup_configuration", eaB(false), "enhanced_monitoring", eaB(false), "error_report_configuration", eaS("3389"), "health_check", eaB(false), "kms_key_arn", eaS("password123"), "log_publishing_options", eaB(false), "logging_configurations", eaB(false), "number_of_broker_nodes", eaS("public"), "path", eaS("public"), "privileged", eaB(true), "result_configuration", eaS("public"), "retention_days", eaN(1.0), "root_access", eaS("Allow"), "rule", eaS("public"), "s3_configuration", eaS("public"), "server_side_encryption", eaB(false), "shard_level_metrics", eaS("public"), "skip_final_snapshot", eaS("public"), "text_data_delivery", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-821: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-821: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-821: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_athena_workgroup", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-821: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_athena_workgroup", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-821: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_822(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-822")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_kinesis_stream", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-822: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-822: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-822: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_kinesis_stream", "probe", map[string]ir.Value{
			"Enabled":                         eaB(false),
			"PER_TOPIC_PER_BROKER":            eaS("public"),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaS("public"),
			"absent":                          eaS("public"),
			"advanced_security_options":       eaB(false),
			"app_network_access_type":         eaS("String"),
			"client_broker":                   eaS("public"),
			"configuration":                   eaS("public"),
			"container_properties":            eaS("public"),
			"content_policy_config":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"copy_tags_to_snapshot":           eaS("latest"),
			"data_capture_config":             eaS("public"),
			"direct_internet_access":          eaS("Allow"),
			"enabled":                         eaB(false),
			"encryption_configuration":        eaB(false),
			"encryption_info":                 eaB(false),
			"encryption_option":               eaB(false),
			"enforce_workgroup_configuration": eaB(false),
			"enhanced_monitoring":             eaB(false),
			"error_report_configuration":      eaS("3389"),
			"health_check":                    eaB(false),
			"kms_key_arn":                     eaS("password123"),
			"log_publishing_options":          eaB(false),
			"logging_configurations":          eaB(false),
			"number_of_broker_nodes":          eaS("public"),
			"path":                            eaS("public"),
			"privileged":                      eaB(true),
			"result_configuration":            eaS("public"),
			"retention_days":                  eaN(1.0),
			"root_access":                     eaS("Allow"),
			"s3_configuration":                eaS("public"),
			"server_side_encryption":          eaB(false),
			"shard_level_metrics":             eaS("public"),
			"skip_final_snapshot":             eaS("public"),
			"text_data_delivery":              eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-822: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_kinesis_stream", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-822: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_823(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-823")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_kinesis_firehose_delivery_stream", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-823: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-823: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-823: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_kinesis_firehose_delivery_stream", "probe", map[string]ir.Value{
			"Enabled":                         eaB(false),
			"PER_TOPIC_PER_BROKER":            eaS("public"),
			"PLAINTEXT":                       eaB(true),
			"PublicInternetOnly":              eaB(true),
			"SSE_KMS":                         eaS("public"),
			"absent":                          eaS("public"),
			"advanced_security_options":       eaB(false),
			"app_network_access_type":         eaS("String"),
			"client_broker":                   eaS("public"),
			"configuration":                   eaS("public"),
			"container_properties":            eaS("public"),
			"content_policy_config":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"copy_tags_to_snapshot":           eaS("latest"),
			"data_capture_config":             eaS("public"),
			"direct_internet_access":          eaS("Allow"),
			"enabled":                         eaB(false),
			"encryption_configuration":        eaB(false),
			"encryption_info":                 eaB(false),
			"encryption_option":               eaB(false),
			"enforce_workgroup_configuration": eaB(false),
			"enhanced_monitoring":             eaB(false),
			"error_report_configuration":      eaS("3389"),
			"health_check":                    eaB(false),
			"kms_key_arn":                     eaS("password123"),
			"log_publishing_options":          eaB(false),
			"logging_configurations":          eaB(false),
			"number_of_broker_nodes":          eaS("public"),
			"path":                            eaS("public"),
			"privileged":                      eaB(true),
			"result_configuration":            eaS("public"),
			"retention_days":                  eaN(1.0),
			"root_access":                     eaS("Allow"),
			"rule":                            eaS("public"),
			"s3_configuration":                eaS("public"),
			"server_side_encryption":          eaB(false),
			"shard_level_metrics":             eaS("public"),
			"skip_final_snapshot":             eaS("public"),
			"text_data_delivery":              eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-823: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_kinesis_firehose_delivery_stream", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-823: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_824(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-824")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_timestreamquery_scheduled_query", "probe", map[string]ir.Value{
			"error_report_configuration": eaL(eaM("s3_configuration", eaL(eaM("Enabled", eaS("*"), "PER_TOPIC_PER_BROKER", eaS("*"), "PLAINTEXT", eaS("*"), "PublicInternetOnly", eaS("*"), "SSE_KMS", eaS("*"), "absent", eaS("*"), "advanced_security_options", eaS("*"), "app_network_access_type", eaS("*"), "client_broker", eaS("*"), "configuration", eaS("*"), "container_properties", eaS("*"), "content_policy_config", eaS("*"), "copy_tags_to_snapshot", eaS("*"), "data_capture_config", eaS("*"), "direct_internet_access", eaS("*"), "enabled", eaS("*"), "encryption_configuration", eaS("*"), "encryption_info", eaS("*"), "encryption_option", eaS("*"), "enforce_workgroup_configuration", eaS("*"), "enhanced_monitoring", eaS("*"), "error_report_configuration", eaS("*"), "health_check", eaS("*"), "kms_key_arn", eaS("*"), "log_publishing_options", eaS("*"), "logging_configurations", eaS("*"), "number_of_broker_nodes", eaS("*"), "path", eaS("*"), "privileged", eaS("*"), "result_configuration", eaS("*"), "retention_days", eaS("*"), "root_access", eaS("*"), "rule", eaS("*"), "s3_configuration", eaS("*"), "server_side_encryption", eaS("*"), "shard_level_metrics", eaS("*"), "skip_final_snapshot", eaS("*"), "text_data_delivery", eaS("*"))))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-824: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-824: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-824: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_timestreamquery_scheduled_query", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-824: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_timestreamquery_scheduled_query", "probe", map[string]ir.Value{
		"Enabled":                         eaU(),
		"PER_TOPIC_PER_BROKER":            eaU(),
		"PLAINTEXT":                       eaU(),
		"PublicInternetOnly":              eaU(),
		"SSE_KMS":                         eaU(),
		"absent":                          eaU(),
		"advanced_security_options":       eaU(),
		"app_network_access_type":         eaU(),
		"bucket":                          eaU(),
		"client_broker":                   eaU(),
		"configuration":                   eaU(),
		"container_properties":            eaU(),
		"content_policy_config":           eaU(),
		"copy_tags_to_snapshot":           eaU(),
		"data_capture_config":             eaU(),
		"direct_internet_access":          eaU(),
		"enabled":                         eaU(),
		"encryption_configuration":        eaU(),
		"encryption_info":                 eaU(),
		"encryption_option":               eaU(),
		"enforce_workgroup_configuration": eaU(),
		"enhanced_monitoring":             eaU(),
		"error_report_configuration":      eaU(),
		"false":                           eaU(),
		"health_check":                    eaU(),
		"kms_key_arn":                     eaU(),
		"log_publishing_options":          eaU(),
		"logging_configurations":          eaU(),
		"number_of_broker_nodes":          eaU(),
		"path":                            eaU(),
		"privileged":                      eaU(),
		"result_configuration":            eaU(),
		"retention_days":                  eaU(),
		"root_access":                     eaU(),
		"rule":                            eaU(),
		"s3_configuration":                eaU(),
		"server_side_encryption":          eaU(),
		"shard_level_metrics":             eaU(),
		"skip_final_snapshot":             eaU(),
		"strings":                         eaU(),
		"target_bucket":                   eaU(),
		"text_data_delivery":              eaU(),
		"true":                            eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-824: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_828(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-828")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_cloudfront_distribution", "probe", map[string]ir.Value{
			"ALL":                        eaB(true),
			"DISABLED":                   eaB(true),
			"FTP":                        eaB(true),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaB(true),
			"TLS_1_0":                    eaB(true),
			"allow_origins":              eaB(true),
			"backup_vault_name":          eaB(true),
			"cloudwatch_role_arn":        eaB(true),
			"copy_action":                eaB(true),
			"cors_configuration":         eaB(true),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaB(true),
			"feature_set":                eaB(true),
			"force_destroy":              eaB(true),
			"health_check":               eaB(true),
			"min_retention_days":         eaB(true),
			"name":                       eaB(true),
			"options":                    eaB(true),
			"origin":                     eaB(true),
			"origin_access_identity":     eaB(true),
			"price_class":                eaB(true),
			"protocol":                   eaB(true),
			"protocols":                  eaB(true),
			"request_validator_id":       eaB(true),
			"response_headers_policy_id": eaB(true),
			"rule":                       eaB(true),
			"s3_origin_config":           eaB(true),
			"security_policy":            eaB(true),
			"ssl_policy":                 eaB(true),
			"staging":                    eaB(true),
			"state":                      eaB(true),
			"static_routes_only":         eaB(true),
			"throttle_settings":          eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-828: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-828: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-828: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_cloudfront_distribution", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-828: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_cloudfront_distribution", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-828: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_829(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-829")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_api_gatewayv2_api", "probe", map[string]ir.Value{
			"ALL":                        eaS("public"),
			"DISABLED":                   eaB(true),
			"FTP":                        eaS("public"),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaS("public"),
			"TLS_1_0":                    eaS("public"),
			"allow_origins":              eaL(eaS("*")),
			"backup_vault_name":          eaS("my_password"),
			"cloudwatch_role_arn":        eaS("roles/owner"),
			"copy_action":                eaL(eaS("*")),
			"cors_configuration":         eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaS("my_password"),
			"feature_set":                eaS("public"),
			"force_destroy":              eaS("public"),
			"health_check":               eaB(false),
			"min_retention_days":         eaN(1.0),
			"name":                       eaS("my_password"),
			"options":                    eaS("public"),
			"origin":                     eaS("public"),
			"origin_access_identity":     eaS("Allow"),
			"price_class":                eaS("public"),
			"protocol":                   eaS("Tcp"),
			"protocols":                  eaS("Tcp"),
			"request_validator_id":       eaS("public"),
			"response_headers_policy_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"rule":                       eaS("public"),
			"s3_origin_config":           eaS("public"),
			"security_policy":            eaS("TLS_1_0"),
			"ssl_policy":                 eaS("TLS_1_0"),
			"staging":                    eaS("latest"),
			"state":                      eaS("public"),
			"static_routes_only":         eaS("public"),
			"throttle_settings":          eaN(1.0),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-829: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-829: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-829: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_api_gatewayv2_api", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-829: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_api_gatewayv2_api", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-829: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_832(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-832")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_apigatewayv2_domain_name", "probe", map[string]ir.Value{
			"domain_name_configuration": eaL(eaM("ALL", eaS("public"), "DISABLED", eaB(true), "FTP", eaS("public"), "HTTP", eaB(true), "PriceClass_All", eaS("public"), "TLS_1_0", eaS("public"), "allow_origins", eaL(eaS("*")), "backup_vault_name", eaS("my_password"), "cloudwatch_role_arn", eaS("roles/owner"), "copy_action", eaL(eaS("*")), "cors_configuration", eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))), "disabled", eaB(true), "domain_name_configuration", eaS("my_password"), "feature_set", eaS("public"), "force_destroy", eaS("public"), "health_check", eaB(false), "min_retention_days", eaN(1.0), "name", eaS("my_password"), "options", eaS("public"), "origin", eaS("public"), "origin_access_identity", eaS("Allow"), "price_class", eaS("public"), "protocol", eaS("Tcp"), "protocols", eaS("Tcp"), "request_validator_id", eaS("public"), "response_headers_policy_id", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "rule", eaS("public"), "s3_origin_config", eaS("public"), "security_policy", eaS("TLS_1_0"), "ssl_policy", eaS("TLS_1_0"), "staging", eaS("latest"), "state", eaS("public"), "static_routes_only", eaS("public"), "throttle_settings", eaN(1.0))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-832: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-832: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-832: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_apigatewayv2_domain_name", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-832: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_apigatewayv2_domain_name", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-832: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_833(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-833")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_route53_zone", "probe", map[string]ir.Value{
			"ALL":                        eaB(true),
			"DISABLED":                   eaB(true),
			"FTP":                        eaB(true),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaB(true),
			"TLS_1_0":                    eaB(true),
			"allow_origins":              eaB(true),
			"backup_vault_name":          eaB(true),
			"cloudwatch_role_arn":        eaB(true),
			"copy_action":                eaB(true),
			"cors_configuration":         eaB(true),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaB(true),
			"feature_set":                eaB(true),
			"force_destroy":              eaB(true),
			"health_check":               eaB(true),
			"min_retention_days":         eaB(true),
			"name":                       eaB(true),
			"options":                    eaB(true),
			"origin":                     eaB(true),
			"origin_access_identity":     eaB(true),
			"price_class":                eaB(true),
			"protocol":                   eaB(true),
			"protocols":                  eaB(true),
			"request_validator_id":       eaB(true),
			"response_headers_policy_id": eaB(true),
			"rule":                       eaB(true),
			"s3_origin_config":           eaB(true),
			"security_policy":            eaB(true),
			"ssl_policy":                 eaB(true),
			"staging":                    eaB(true),
			"state":                      eaB(true),
			"static_routes_only":         eaB(true),
			"throttle_settings":          eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-833: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-833: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-833: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_route53_zone", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-833: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_route53_zone", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-833: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_838(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-838")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_organizations_organizational_unit", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-838: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-838: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-838: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_organizations_organizational_unit", "probe", map[string]ir.Value{
			"ALL":                        eaS("public"),
			"DISABLED":                   eaB(true),
			"FTP":                        eaS("public"),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaS("public"),
			"TLS_1_0":                    eaS("public"),
			"allow_origins":              eaL(eaS("*")),
			"backup_vault_name":          eaS("my_password"),
			"cloudwatch_role_arn":        eaS("roles/owner"),
			"copy_action":                eaL(eaS("*")),
			"cors_configuration":         eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaS("my_password"),
			"feature_set":                eaS("public"),
			"force_destroy":              eaS("public"),
			"health_check":               eaB(false),
			"min_retention_days":         eaN(1.0),
			"name":                       eaS("my_password"),
			"options":                    eaS("public"),
			"origin":                     eaS("public"),
			"origin_access_identity":     eaS("Allow"),
			"price_class":                eaS("public"),
			"protocol":                   eaS("Tcp"),
			"protocols":                  eaS("Tcp"),
			"request_validator_id":       eaS("public"),
			"response_headers_policy_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"rule":                       eaS("public"),
			"s3_origin_config":           eaS("public"),
			"security_policy":            eaS("TLS_1_0"),
			"ssl_policy":                 eaS("TLS_1_0"),
			"staging":                    eaS("latest"),
			"state":                      eaS("public"),
			"static_routes_only":         eaS("public"),
			"throttle_settings":          eaN(1.0),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-838: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_organizations_organizational_unit", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-838: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_841(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-841")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_lb_target_group", "probe", map[string]ir.Value{
			"health_check": eaL(eaM("ALL", eaS("HTTP"), "DISABLED", eaS("HTTP"), "FTP", eaS("HTTP"), "HTTP", eaS("HTTP"), "PriceClass_All", eaS("HTTP"), "TLS_1_0", eaS("HTTP"), "allow_origins", eaS("HTTP"), "backup_vault_name", eaS("HTTP"), "cloudwatch_role_arn", eaS("HTTP"), "copy_action", eaS("HTTP"), "cors_configuration", eaS("HTTP"), "disabled", eaS("HTTP"), "domain_name_configuration", eaS("HTTP"), "feature_set", eaS("HTTP"), "force_destroy", eaS("HTTP"), "health_check", eaS("HTTP"), "min_retention_days", eaS("HTTP"), "name", eaS("HTTP"), "options", eaS("HTTP"), "origin", eaS("HTTP"), "origin_access_identity", eaS("HTTP"), "price_class", eaS("HTTP"), "protocol", eaS("HTTP"), "protocols", eaS("HTTP"), "request_validator_id", eaS("HTTP"), "response_headers_policy_id", eaS("HTTP"), "rule", eaS("HTTP"), "s3_origin_config", eaS("HTTP"), "security_policy", eaS("HTTP"), "ssl_policy", eaS("HTTP"), "staging", eaS("HTTP"), "state", eaS("HTTP"), "static_routes_only", eaS("HTTP"), "throttle_settings", eaS("HTTP"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-841: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-841: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-841: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_lb_target_group", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-841: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_lb_target_group", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-841: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_843(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-843")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_api_gateway_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-843: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-843: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-843: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_api_gateway_account", "probe", map[string]ir.Value{
			"ALL":                        eaS("public"),
			"DISABLED":                   eaB(true),
			"FTP":                        eaS("public"),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaS("public"),
			"TLS_1_0":                    eaS("public"),
			"allow_origins":              eaL(eaS("*")),
			"backup_vault_name":          eaS("my_password"),
			"cloudwatch_role_arn":        eaS("roles/owner"),
			"copy_action":                eaL(eaS("*")),
			"cors_configuration":         eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaS("my_password"),
			"feature_set":                eaS("public"),
			"force_destroy":              eaS("public"),
			"health_check":               eaB(false),
			"min_retention_days":         eaN(1.0),
			"name":                       eaS("my_password"),
			"options":                    eaS("public"),
			"origin":                     eaS("public"),
			"origin_access_identity":     eaS("Allow"),
			"price_class":                eaS("public"),
			"protocol":                   eaS("Tcp"),
			"protocols":                  eaS("Tcp"),
			"request_validator_id":       eaS("public"),
			"response_headers_policy_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"rule":                       eaS("public"),
			"s3_origin_config":           eaS("public"),
			"security_policy":            eaS("TLS_1_0"),
			"ssl_policy":                 eaS("TLS_1_0"),
			"staging":                    eaS("latest"),
			"state":                      eaS("public"),
			"static_routes_only":         eaS("public"),
			"throttle_settings":          eaN(1.0),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-843: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_api_gateway_account", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-843: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_844(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-844")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_api_gateway_method", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-844: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-844: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-844: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_api_gateway_method", "probe", map[string]ir.Value{
			"ALL":                        eaS("public"),
			"DISABLED":                   eaB(true),
			"FTP":                        eaS("public"),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaS("public"),
			"TLS_1_0":                    eaS("public"),
			"allow_origins":              eaL(eaS("*")),
			"backup_vault_name":          eaS("my_password"),
			"cloudwatch_role_arn":        eaS("roles/owner"),
			"copy_action":                eaL(eaS("*")),
			"cors_configuration":         eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaS("my_password"),
			"feature_set":                eaS("public"),
			"force_destroy":              eaS("public"),
			"health_check":               eaB(false),
			"min_retention_days":         eaN(1.0),
			"name":                       eaS("my_password"),
			"options":                    eaS("public"),
			"origin":                     eaS("public"),
			"origin_access_identity":     eaS("Allow"),
			"price_class":                eaS("public"),
			"protocol":                   eaS("Tcp"),
			"protocols":                  eaS("Tcp"),
			"request_validator_id":       eaS("public"),
			"response_headers_policy_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"rule":                       eaS("public"),
			"s3_origin_config":           eaS("public"),
			"security_policy":            eaS("TLS_1_0"),
			"ssl_policy":                 eaS("TLS_1_0"),
			"staging":                    eaS("latest"),
			"state":                      eaS("public"),
			"static_routes_only":         eaS("public"),
			"throttle_settings":          eaN(1.0),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-844: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_api_gateway_method", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-844: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_845(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-845")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_api_gateway_usage_plan", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-845: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-845: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-845: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_api_gateway_usage_plan", "probe", map[string]ir.Value{
			"ALL":                        eaS("public"),
			"DISABLED":                   eaB(true),
			"FTP":                        eaS("public"),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaS("public"),
			"TLS_1_0":                    eaS("public"),
			"allow_origins":              eaL(eaS("*")),
			"backup_vault_name":          eaS("my_password"),
			"cloudwatch_role_arn":        eaS("roles/owner"),
			"copy_action":                eaL(eaS("*")),
			"cors_configuration":         eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaS("my_password"),
			"feature_set":                eaS("public"),
			"force_destroy":              eaS("public"),
			"health_check":               eaB(false),
			"min_retention_days":         eaN(1.0),
			"name":                       eaS("my_password"),
			"options":                    eaS("public"),
			"origin":                     eaS("public"),
			"origin_access_identity":     eaS("Allow"),
			"price_class":                eaS("public"),
			"protocol":                   eaS("Tcp"),
			"protocols":                  eaS("Tcp"),
			"request_validator_id":       eaS("public"),
			"response_headers_policy_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"rule":                       eaS("public"),
			"s3_origin_config":           eaS("public"),
			"security_policy":            eaS("TLS_1_0"),
			"ssl_policy":                 eaS("TLS_1_0"),
			"staging":                    eaS("latest"),
			"state":                      eaS("public"),
			"static_routes_only":         eaS("public"),
			"throttle_settings":          eaN(1.0),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-845: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_api_gateway_usage_plan", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-845: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_846(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-846")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_route53_health_check", "probe", map[string]ir.Value{
			"ALL":                        eaS("public"),
			"DISABLED":                   eaB(true),
			"FTP":                        eaS("public"),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaS("public"),
			"TLS_1_0":                    eaS("public"),
			"allow_origins":              eaL(eaS("*")),
			"backup_vault_name":          eaS("my_password"),
			"cloudwatch_role_arn":        eaS("roles/owner"),
			"copy_action":                eaL(eaS("*")),
			"cors_configuration":         eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaS("my_password"),
			"feature_set":                eaS("public"),
			"force_destroy":              eaS("public"),
			"health_check":               eaB(false),
			"min_retention_days":         eaN(1.0),
			"name":                       eaS("my_password"),
			"options":                    eaS("public"),
			"origin":                     eaS("public"),
			"origin_access_identity":     eaS("Allow"),
			"price_class":                eaS("public"),
			"protocol":                   eaS("Tcp"),
			"protocols":                  eaS("Tcp"),
			"request_validator_id":       eaS("public"),
			"response_headers_policy_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"rule":                       eaS("public"),
			"s3_origin_config":           eaS("public"),
			"security_policy":            eaS("TLS_1_0"),
			"ssl_policy":                 eaS("TLS_1_0"),
			"staging":                    eaS("latest"),
			"state":                      eaS("public"),
			"static_routes_only":         eaS("public"),
			"throttle_settings":          eaN(1.0),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-846: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-846: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-846: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_route53_health_check", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-846: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_route53_health_check", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-846: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AWS_848(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AWS-848")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("aws_vpn_connection", "probe", map[string]ir.Value{
			"ALL":                        eaB(true),
			"DISABLED":                   eaB(true),
			"FTP":                        eaB(true),
			"HTTP":                       eaB(true),
			"PriceClass_All":             eaB(true),
			"TLS_1_0":                    eaB(true),
			"allow_origins":              eaB(true),
			"backup_vault_name":          eaB(true),
			"cloudwatch_role_arn":        eaB(true),
			"copy_action":                eaB(true),
			"cors_configuration":         eaB(true),
			"disabled":                   eaB(true),
			"domain_name_configuration":  eaB(true),
			"feature_set":                eaB(true),
			"force_destroy":              eaB(true),
			"health_check":               eaB(true),
			"min_retention_days":         eaB(true),
			"name":                       eaB(true),
			"options":                    eaB(true),
			"origin":                     eaB(true),
			"origin_access_identity":     eaB(true),
			"price_class":                eaB(true),
			"protocol":                   eaB(true),
			"protocols":                  eaB(true),
			"request_validator_id":       eaB(true),
			"response_headers_policy_id": eaB(true),
			"rule":                       eaB(true),
			"s3_origin_config":           eaB(true),
			"security_policy":            eaB(true),
			"ssl_policy":                 eaB(true),
			"staging":                    eaB(true),
			"state":                      eaB(true),
			"static_routes_only":         eaB(true),
			"throttle_settings":          eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AWS-848: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AWS-848: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AWS-848: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("aws_vpn_connection", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-848: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("aws_vpn_connection", "probe", map[string]ir.Value{
		"ALL":                        eaU(),
		"DISABLED":                   eaU(),
		"FTP":                        eaU(),
		"HTTP":                       eaU(),
		"PriceClass_All":             eaU(),
		"TLS_1_0":                    eaU(),
		"allow_origins":              eaU(),
		"backup_vault_name":          eaU(),
		"bucket":                     eaU(),
		"cloudwatch_role_arn":        eaU(),
		"copy_action":                eaU(),
		"cors_configuration":         eaU(),
		"disabled":                   eaU(),
		"domain_name_configuration":  eaU(),
		"feature_set":                eaU(),
		"force_destroy":              eaU(),
		"health_check":               eaU(),
		"min_retention_days":         eaU(),
		"name":                       eaU(),
		"options":                    eaU(),
		"origin":                     eaU(),
		"origin_access_identity":     eaU(),
		"price_class":                eaU(),
		"protocol":                   eaU(),
		"protocols":                  eaU(),
		"request_validator_id":       eaU(),
		"response_headers_policy_id": eaU(),
		"rule":                       eaU(),
		"s3_origin_config":           eaU(),
		"security_policy":            eaU(),
		"ssl_policy":                 eaU(),
		"staging":                    eaU(),
		"state":                      eaU(),
		"static_routes_only":         eaU(),
		"strings":                    eaU(),
		"target_bucket":              eaU(),
		"throttle_settings":          eaU(),
		"true":                       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AWS-848: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
