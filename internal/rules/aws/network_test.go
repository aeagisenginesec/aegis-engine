package aws

import (
	"testing"

	"aegis/internal/ir"
)

// unknownAttr builds an unresolved attribute value.
func unknownAttr(line int) ir.Value {
	return ir.Value{Known: false, Span: spanAt(line)}
}

func TestNetworkRules_IDsInOrder(t *testing.T) {
	rules := NetworkRules()
	want := []string{
		"AEGIS-AWS-323", "AEGIS-AWS-324", "AEGIS-AWS-325", "AEGIS-AWS-326",
		"AEGIS-AWS-327", "AEGIS-AWS-328", "AEGIS-AWS-329", "AEGIS-AWS-330",
		"AEGIS-AWS-331", "AEGIS-AWS-332",
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("rule %d: got %s, want %s", i, rules[i].ID(), w)
		}
	}
}

// --- 323: LB without deletion protection ---

func Test323_FiresAbsent(t *testing.T) {
	for _, typ := range []string{"aws_lb", "aws_alb"} {
		fs := runRule(lbNoDeletionProtection{}, res(typ, "web", map[string]ir.Value{}))
		if len(fs) != 1 {
			t.Fatalf("%s: got %d findings, want 1", typ, len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("%s: wrong severity %q", typ, fs[0].Severity)
		}
	}
}

func Test323_FiresFalse(t *testing.T) {
	fs := runRule(lbNoDeletionProtection{}, res("aws_lb", "web",
		map[string]ir.Value{"enable_deletion_protection": kv(false, 4)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test323_ProtectedQuiet(t *testing.T) {
	fs := runRule(lbNoDeletionProtection{}, res("aws_lb", "web",
		map[string]ir.Value{"enable_deletion_protection": kv(true, 4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test323_UnknownQuiet(t *testing.T) {
	fs := runRule(lbNoDeletionProtection{}, res("aws_lb", "web",
		map[string]ir.Value{"enable_deletion_protection": unknownAttr(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 324: listener with weak TLS policy ---

func Test324_FiresWeakPolicy(t *testing.T) {
	fs := runRule(lbListenerWeakTLS{}, res("aws_lb_listener", "https",
		map[string]ir.Value{
			"protocol":   ks("HTTPS", 3),
			"ssl_policy": ks("ELBSecurityPolicy-2016-08", 4),
		}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Evidence.Attribute != "ssl_policy" {
		t.Fatalf("wrong evidence attribute %q", fs[0].Evidence.Attribute)
	}
}

func Test324_FiresOldPolicies(t *testing.T) {
	for _, pol := range []string{
		"ELBSecurityPolicy-2016-08",
		"ELBSecurityPolicy-TLS-1-1-2017-01",
		"ELBSecurityPolicy-TLS-1-0-2015-04",
	} {
		fs := runRule(lbListenerWeakTLS{}, res("aws_lb_listener", "https",
			map[string]ir.Value{
				"protocol":   ks("HTTPS", 3),
				"ssl_policy": ks(pol, 4),
			}))
		if len(fs) != 1 {
			t.Fatalf("policy %q: got %d findings, want 1", pol, len(fs))
		}
	}
}
func Test324_StrongPolicyQuiet(t *testing.T) {
	for _, pol := range []string{
		"ELBSecurityPolicy-TLS13-1-2-2021-06",
		"ELBSecurityPolicy-TLS-1-2-2017-01",
		"ELBSecurityPolicy-FS-1-2-Res-2020-10",
	} {
		fs := runRule(lbListenerWeakTLS{}, res("aws_alb_listener", "https",
			map[string]ir.Value{
				"protocol":   ks("HTTPS", 3),
				"ssl_policy": ks(pol, 4),
			}))
		if len(fs) != 0 {
			t.Fatalf("policy %q: got %d findings, want 0", pol, len(fs))
		}
	}
}

func Test324_PlainHTTPOutOfScope(t *testing.T) {
	fs := runRule(lbListenerWeakTLS{}, res("aws_lb_listener", "http",
		map[string]ir.Value{
			"protocol":   ks("HTTP", 3),
			"ssl_policy": ks("ELBSecurityPolicy-2016-08", 4),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0 (plain HTTP is rule 202)", len(fs))
	}
}

func Test324_AbsentPolicyFires(t *testing.T) {
	// Absent ssl_policy on an HTTPS listener: AWS applies
	// ELBSecurityPolicy-2016-08 (pre-TLS-1.2) — fail closed.
	fs := runRule(lbListenerWeakTLS{}, res("aws_lb_listener", "https",
		map[string]ir.Value{"protocol": ks("HTTPS", 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].RuleID != "AEGIS-AWS-324" {
		t.Fatalf("got rule %s, want AEGIS-AWS-324", fs[0].RuleID)
	}
}

func Test324_UnknownQuiet(t *testing.T) {
	fs := runRule(lbListenerWeakTLS{}, res("aws_lb_listener", "https",
		map[string]ir.Value{
			"protocol":   ks("HTTPS", 3),
			"ssl_policy": unknownAttr(4),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
	fs2 := runRule(lbListenerWeakTLS{}, res("aws_lb_listener", "https",
		map[string]ir.Value{
			"protocol":   unknownAttr(3),
			"ssl_policy": ks("ELBSecurityPolicy-2016-08", 4),
		}))
	if len(fs2) != 0 {
		t.Fatalf("unknown protocol: got %d findings, want 0", len(fs2))
	}
}

// --- 325: CloudFront allows HTTP ---

func Test325_FiresDefaultBehavior(t *testing.T) {
	fs := runRule(cloudfrontAllowsHTTP{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{
			"default_cache_behavior": blks(5, blk("viewer_protocol_policy", ks("allow-all", 6))),
		}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test325_FiresOrderedBehavior(t *testing.T) {
	fs := runRule(cloudfrontAllowsHTTP{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{
			"default_cache_behavior": blks(5, blk("viewer_protocol_policy", ks("https-only", 6))),
			"ordered_cache_behavior": blks(8,
				blk("viewer_protocol_policy", ks("redirect-to-https", 9)),
				blk("viewer_protocol_policy", ks("allow-all", 12))),
		}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test325_HTTPSOnlyQuiet(t *testing.T) {
	fs := runRule(cloudfrontAllowsHTTP{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{
			"default_cache_behavior": blks(5, blk("viewer_protocol_policy", ks("https-only", 6))),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test325_UnknownQuiet(t *testing.T) {
	fs := runRule(cloudfrontAllowsHTTP{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{
			"default_cache_behavior": blks(5, blk("viewer_protocol_policy", unknownAttr(6))),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
	fs2 := runRule(cloudfrontAllowsHTTP{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{"default_cache_behavior": unknownAttr(5)}))
	if len(fs2) != 0 {
		t.Fatalf("unknown block: got %d findings, want 0", len(fs2))
	}
}

// --- 326: API Gateway custom domain weak TLS ---

func Test326_FiresTLS10(t *testing.T) {
	fs := runRule(apiGwDomainWeakTLS{}, res("aws_api_gateway_domain_name", "api",
		map[string]ir.Value{"security_policy": ks("TLS_1_0", 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test326_TLS12Quiet(t *testing.T) {
	fs := runRule(apiGwDomainWeakTLS{}, res("aws_api_gateway_domain_name", "api",
		map[string]ir.Value{"security_policy": ks("TLS_1_2", 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test326_AbsentQuiet(t *testing.T) {
	fs := runRule(apiGwDomainWeakTLS{}, res("aws_api_gateway_domain_name", "api",
		map[string]ir.Value{}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test326_UnknownQuiet(t *testing.T) {
	fs := runRule(apiGwDomainWeakTLS{}, res("aws_api_gateway_domain_name", "api",
		map[string]ir.Value{"security_policy": unknownAttr(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 327: API Gateway stage without access logging ---

func Test327_FiresAbsent(t *testing.T) {
	fs := runRule(apiGwStageNoAccessLog{}, res("aws_api_gateway_stage", "prod",
		map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test327_LoggedQuiet(t *testing.T) {
	fs := runRule(apiGwStageNoAccessLog{}, res("aws_api_gateway_stage", "prod",
		map[string]ir.Value{
			"access_log_settings": blks(4, blk("destination_arn", ks("arn:aws:logs:x", 5))),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test327_UnknownQuiet(t *testing.T) {
	fs := runRule(apiGwStageNoAccessLog{}, res("aws_api_gateway_stage", "prod",
		map[string]ir.Value{"access_log_settings": unknownAttr(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 328: NACL inline ingress open ---

func Test328_FiresOpenIngress(t *testing.T) {
	fs := runRule(naclOpenIngress{}, res("aws_network_acl", "main",
		map[string]ir.Value{
			"ingress": blks(4,
				blk("cidr_block", ks("10.0.0.0/8", 5), "action", ks("allow", 6)),
				blk("cidr_block", ks("0.0.0.0/0", 8), "action", ks("allow", 9))),
		}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test328_DenyQuiet(t *testing.T) {
	fs := runRule(naclOpenIngress{}, res("aws_network_acl", "main",
		map[string]ir.Value{
			"ingress": blks(4,
				blk("cidr_block", ks("0.0.0.0/0", 5), "action", ks("deny", 6))),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test328_UnknownQuiet(t *testing.T) {
	fs := runRule(naclOpenIngress{}, res("aws_network_acl", "main",
		map[string]ir.Value{
			"ingress": blks(4,
				blk("cidr_block", unknownAttr(5), "action", ks("allow", 6))),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
	fs2 := runRule(naclOpenIngress{}, res("aws_network_acl", "main",
		map[string]ir.Value{
			"ingress": blks(4,
				blk("cidr_block", ks("0.0.0.0/0", 5), "action", unknownAttr(6))),
		}))
	if len(fs2) != 0 {
		t.Fatalf("unknown action: got %d findings, want 0", len(fs2))
	}
}

func Test328_WrongTypeSkipped(t *testing.T) {
	fs := runRule(naclOpenIngress{}, res("aws_network_acl_rule", "open",
		map[string]ir.Value{
			"cidr_block":  ks("0.0.0.0/0", 3),
			"rule_action": ks("allow", 4),
		}))
	if len(fs) != 0 {
		t.Fatalf("328 must not apply to standalone rule resources, got %d", len(fs))
	}
}

// --- 329: LB target group plain HTTP ---

func Test329_FiresHTTP(t *testing.T) {
	fs := runRule(lbTargetGroupPlainHTTP{}, res("aws_lb_target_group", "app",
		map[string]ir.Value{"protocol": ks("HTTP", 4)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test329_HTTPSQuiet(t *testing.T) {
	fs := runRule(lbTargetGroupPlainHTTP{}, res("aws_lb_target_group", "app",
		map[string]ir.Value{"protocol": ks("HTTPS", 4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test329_UnknownQuiet(t *testing.T) {
	fs := runRule(lbTargetGroupPlainHTTP{}, res("aws_lb_target_group", "app",
		map[string]ir.Value{"protocol": unknownAttr(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
	fs2 := runRule(lbTargetGroupPlainHTTP{}, res("aws_lb_target_group", "app",
		map[string]ir.Value{}))
	if len(fs2) != 0 {
		t.Fatalf("absent protocol: got %d findings, want 0", len(fs2))
	}
}

// --- 330: CloudFront without WAF ---

func Test330_FiresAbsent(t *testing.T) {
	fs := runRule(cloudfrontNoWAF{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test330_FiresEmpty(t *testing.T) {
	fs := runRule(cloudfrontNoWAF{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{"web_acl_id": ks("", 5)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test330_WAFAttachedQuiet(t *testing.T) {
	fs := runRule(cloudfrontNoWAF{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{"web_acl_id": ks("arn:aws:wafv2:us-east-1:123:webacl/x", 5)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test330_UnknownQuiet(t *testing.T) {
	fs := runRule(cloudfrontNoWAF{}, res("aws_cloudfront_distribution", "cdn",
		map[string]ir.Value{"web_acl_id": unknownAttr(5)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 331: standalone NACL rule open ingress ---

func Test331_FiresOpenIngress(t *testing.T) {
	fs := runRule(naclRuleOpenIngress{}, res("aws_network_acl_rule", "open",
		map[string]ir.Value{
			"cidr_block":  ks("0.0.0.0/0", 3),
			"rule_action": ks("allow", 4),
			"egress":      kv(false, 5),
		}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	fs2 := runRule(naclRuleOpenIngress{}, res("aws_network_acl_rule", "open",
		map[string]ir.Value{
			"cidr_block":  ks("0.0.0.0/0", 3),
			"rule_action": ks("allow", 4),
		}))
	if len(fs2) != 1 {
		t.Fatalf("absent egress (default false): got %d findings, want 1", len(fs2))
	}
}

func Test331_EgressOutOfScope(t *testing.T) {
	fs := runRule(naclRuleOpenIngress{}, res("aws_network_acl_rule", "open",
		map[string]ir.Value{
			"cidr_block":  ks("0.0.0.0/0", 3),
			"rule_action": ks("allow", 4),
			"egress":      kv(true, 5),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test331_DenyQuiet(t *testing.T) {
	fs := runRule(naclRuleOpenIngress{}, res("aws_network_acl_rule", "open",
		map[string]ir.Value{
			"cidr_block":  ks("0.0.0.0/0", 3),
			"rule_action": ks("deny", 4),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test331_UnknownQuiet(t *testing.T) {
	fs := runRule(naclRuleOpenIngress{}, res("aws_network_acl_rule", "open",
		map[string]ir.Value{
			"cidr_block":  unknownAttr(3),
			"rule_action": ks("allow", 4),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
	fs2 := runRule(naclRuleOpenIngress{}, res("aws_network_acl_rule", "open",
		map[string]ir.Value{
			"cidr_block":  ks("0.0.0.0/0", 3),
			"rule_action": ks("allow", 4),
			"egress":      unknownAttr(5),
		}))
	if len(fs2) != 0 {
		t.Fatalf("unknown egress: got %d findings, want 0", len(fs2))
	}
}

// --- 332: API Gateway v2 stage without access logging ---

func Test332_FiresAbsent(t *testing.T) {
	fs := runRule(apiGwV2StageNoAccessLog{}, res("aws_apigatewayv2_stage", "prod",
		map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test332_LoggedQuiet(t *testing.T) {
	fs := runRule(apiGwV2StageNoAccessLog{}, res("aws_apigatewayv2_stage", "prod",
		map[string]ir.Value{
			"access_log_settings": blks(4, blk("destination_arn", ks("arn:aws:logs:x", 5))),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test332_UnknownQuiet(t *testing.T) {
	fs := runRule(apiGwV2StageNoAccessLog{}, res("aws_apigatewayv2_stage", "prod",
		map[string]ir.Value{"access_log_settings": unknownAttr(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}
