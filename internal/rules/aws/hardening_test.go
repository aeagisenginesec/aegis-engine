package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-528: Redshift without enhanced VPC routing
// ---------------------------------------------------------------------------

func Test528_FiresWhenAbsent(t *testing.T) {
	r := res("aws_redshift_cluster", "c", map[string]ir.Value{})
	fs := runRule(redshiftNoEnhancedVPCRouting{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].RuleID != "AEGIS-AWS-528" {
		t.Fatalf("wrong rule id: %s", fs[0].RuleID)
	}
	if fs[0].Evidence.Actual != "absent" {
		t.Fatalf("expected actual=absent, got %q", fs[0].Evidence.Actual)
	}
}

func Test528_FiresWhenFalse(t *testing.T) {
	r := res("aws_redshift_cluster", "c", map[string]ir.Value{
		"enhanced_vpc_routing": kv(false, 3),
	})
	if fs := runRule(redshiftNoEnhancedVPCRouting{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test528_SilentWhenTrue(t *testing.T) {
	r := res("aws_redshift_cluster", "c", map[string]ir.Value{
		"enhanced_vpc_routing": kv(true, 3),
	})
	if fs := runRule(redshiftNoEnhancedVPCRouting{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test528_SilentWhenUnknown(t *testing.T) {
	r := res("aws_redshift_cluster", "c", map[string]ir.Value{
		"enhanced_vpc_routing": ku(3),
	})
	if fs := runRule(redshiftNoEnhancedVPCRouting{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-529: CloudFront without custom SSL certificate
// ---------------------------------------------------------------------------

func cloudfrontRes(pairs ...any) ir.Resource {
	return res("aws_cloudfront_distribution", "d", map[string]ir.Value{
		"viewer_certificate": blks(5, blk(pairs...)),
	})
}

func Test529_FiresWhenDefaultCert(t *testing.T) {
	r := cloudfrontRes("cloudfront_default_certificate", kv(true, 6))
	fs := runRule(cloudfrontDefaultCert{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Evidence.Attribute != "viewer_certificate.cloudfront_default_certificate" {
		t.Fatalf("wrong attribute: %s", fs[0].Evidence.Attribute)
	}
}

func Test529_SilentWhenCustomCert(t *testing.T) {
	r := cloudfrontRes("cloudfront_default_certificate", kv(false, 6))
	if fs := runRule(cloudfrontDefaultCert{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test529_SilentWhenBlockAbsent(t *testing.T) {
	r := res("aws_cloudfront_distribution", "d", map[string]ir.Value{})
	if fs := runRule(cloudfrontDefaultCert{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test529_SilentWhenUnknown(t *testing.T) {
	r := cloudfrontRes("cloudfront_default_certificate", ku(6))
	if fs := runRule(cloudfrontDefaultCert{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-530: WAF web ACL without Log4j protection
// ---------------------------------------------------------------------------

func wafRuleBlock(ruleName string, line int) map[string]ir.Value {
	return blk(
		"name", ks(ruleName, line),
		"statement", blks(line, blk(
			"managed_rule_group_statement", blks(line, blk(
				"name", ks("AWSManagedRulesKnownBadInputsRuleSet", line),
				"vendor_name", ks("AWS", line),
			)),
		)),
	)
}

func wafOtherRuleBlock(line int) map[string]ir.Value {
	return blk(
		"name", ks("rate-limit", line),
		"statement", blks(line, blk(
			"rate_based_statement", blks(line, blk(
				"limit", ks("1000", line),
				"aggregate_key_type", ks("IP", line),
			)),
		)),
	)
}

func wafRes(maps ...map[string]ir.Value) ir.Resource {
	attrs := map[string]ir.Value{}
	if len(maps) > 0 {
		attrs["rule"] = blks(4, maps...)
	}
	return res("aws_wafv2_web_acl", "w", attrs)
}

func Test530_FiresWithoutLog4jGroup(t *testing.T) {
	r := wafRes(wafOtherRuleBlock(5))
	fs := runRule(wafNoLog4jRule{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].RuleID != "AEGIS-AWS-530" {
		t.Fatalf("wrong rule id: %s", fs[0].RuleID)
	}
}

func Test530_SilentWithLog4jGroup(t *testing.T) {
	r := wafRes(wafOtherRuleBlock(5), wafRuleBlock("log4j", 9))
	if fs := runRule(wafNoLog4jRule{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test530_SilentWhenNoRules(t *testing.T) {
	r := wafRes()
	if fs := runRule(wafNoLog4jRule{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test530_SilentWhenRulesUnknown(t *testing.T) {
	r := res("aws_wafv2_web_acl", "w", map[string]ir.Value{
		"rule": ku(4),
	})
	if fs := runRule(wafNoLog4jRule{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-531: CloudFront WAF web ACL without Log4j AMR
// ---------------------------------------------------------------------------

func cloudfrontWAFRes(scope ir.Value, maps ...map[string]ir.Value) ir.Resource {
	attrs := map[string]ir.Value{"scope": scope}
	if len(maps) > 0 {
		attrs["rule"] = blks(4, maps...)
	}
	return res("aws_wafv2_web_acl", "w", attrs)
}

func Test531_FiresForCloudFrontScope(t *testing.T) {
	r := cloudfrontWAFRes(ks("CLOUDFRONT", 2), wafOtherRuleBlock(5))
	fs := runRule(cloudfrontWAFNoLog4jAMR{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].RuleID != "AEGIS-AWS-531" {
		t.Fatalf("wrong rule id: %s", fs[0].RuleID)
	}
}

func Test531_SilentForRegionalScope(t *testing.T) {
	r := cloudfrontWAFRes(ks("REGIONAL", 2), wafOtherRuleBlock(5))
	if fs := runRule(cloudfrontWAFNoLog4jAMR{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test531_SilentWhenCompliant(t *testing.T) {
	r := cloudfrontWAFRes(ks("CLOUDFRONT", 2), wafRuleBlock("log4j", 5))
	if fs := runRule(cloudfrontWAFNoLog4jAMR{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test531_SilentWhenScopeUnknown(t *testing.T) {
	r := cloudfrontWAFRes(ku(2), wafOtherRuleBlock(5))
	if fs := runRule(cloudfrontWAFNoLog4jAMR{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test531_SilentWhenScopeAbsent(t *testing.T) {
	r := wafRes(wafOtherRuleBlock(5))
	if fs := runRule(cloudfrontWAFNoLog4jAMR{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-532: SageMaker notebook allows IMDSv1
// ---------------------------------------------------------------------------

func sagemakerRes(pairs ...any) ir.Resource {
	attrs := map[string]ir.Value{}
	if len(pairs) > 0 {
		attrs["instance_metadata_service_configuration"] = blks(4, blk(pairs...))
	}
	return res("aws_sagemaker_notebook_instance", "n", attrs)
}

func Test532_FiresWhenBlockAbsent(t *testing.T) {
	r := sagemakerRes()
	fs := runRule(sagemakerIMDSv1{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].RuleID != "AEGIS-AWS-532" {
		t.Fatalf("wrong rule id: %s", fs[0].RuleID)
	}
}

func Test532_FiresWhenVersionV1(t *testing.T) {
	r := sagemakerRes("minimum_instance_metadata_service_version", ks("1", 5))
	if fs := runRule(sagemakerIMDSv1{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test532_SilentWhenVersionV2(t *testing.T) {
	r := sagemakerRes("minimum_instance_metadata_service_version", ks("2", 5))
	if fs := runRule(sagemakerIMDSv1{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test532_SilentWhenUnknown(t *testing.T) {
	r := sagemakerRes("minimum_instance_metadata_service_version", ku(5))
	if fs := runRule(sagemakerIMDSv1{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-533: Default security group allows all traffic
// ---------------------------------------------------------------------------

func defaultSGRes(maps ...map[string]ir.Value) ir.Resource {
	attrs := map[string]ir.Value{}
	if len(maps) > 0 {
		attrs["ingress"] = blks(3, maps...)
	}
	return res("aws_default_security_group", "d", attrs)
}

func openIngressBlock(line int) map[string]ir.Value {
	return blk("cidr_blocks", strList(line, "0.0.0.0/0"), "from_port", kv(true, line))
}

func Test533_FiresOnOpenIngress(t *testing.T) {
	r := defaultSGRes(openIngressBlock(4))
	fs := runRule(defaultSGOpen{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].RuleID != "AEGIS-AWS-533" {
		t.Fatalf("wrong rule id: %s", fs[0].RuleID)
	}
	if fs[0].Evidence.Attribute != "ingress.cidr_blocks" {
		t.Fatalf("wrong attribute: %s", fs[0].Evidence.Attribute)
	}
}

func Test533_FiresOnOpenEgress(t *testing.T) {
	r := res("aws_default_security_group", "d", map[string]ir.Value{
		"egress": blks(3, openIngressBlock(4)),
	})
	fs := runRule(defaultSGOpen{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Evidence.Attribute != "egress.cidr_blocks" {
		t.Fatalf("wrong attribute: %s", fs[0].Evidence.Attribute)
	}
}

func Test533_SilentWhenRestricted(t *testing.T) {
	r := defaultSGRes(blk("cidr_blocks", strList(4, "10.0.0.0/8")))
	if fs := runRule(defaultSGOpen{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test533_DoesNotApplyToRegularSG(t *testing.T) {
	rule := defaultSGOpen{}
	if rule.AppliesTo("aws_security_group") {
		t.Fatal("533 must not apply to aws_security_group")
	}
	if !rule.AppliesTo("aws_default_security_group") {
		t.Fatal("533 must apply to aws_default_security_group")
	}
}

func Test533_SilentWhenCIDRsUnknown(t *testing.T) {
	r := defaultSGRes(blk("cidr_blocks", ku(4)))
	if fs := runRule(defaultSGOpen{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// Pack wiring
// ---------------------------------------------------------------------------

func TestHardeningRules_IDOrder(t *testing.T) {
	rules := HardeningRules()
	want := []string{
		"AEGIS-AWS-528", "AEGIS-AWS-529", "AEGIS-AWS-530",
		"AEGIS-AWS-531", "AEGIS-AWS-532", "AEGIS-AWS-533",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("rule %d: expected %s, got %s", i, w, rules[i].ID())
		}
	}
}
