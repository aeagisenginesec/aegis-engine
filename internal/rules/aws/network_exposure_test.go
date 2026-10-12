package aws

import (
	"testing"

	"aegis/internal/ir"
)

func TestNetworkExposureRules_IDsInOrder(t *testing.T) {
	rules := NetworkExposureRules()
	want := []string{
		"AEGIS-AWS-506", "AEGIS-AWS-507", "AEGIS-AWS-508", "AEGIS-AWS-509",
		"AEGIS-AWS-510", "AEGIS-AWS-511", "AEGIS-AWS-512", "AEGIS-AWS-513",
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

// refVal builds an unresolved reference value (Known=false per IR contract).
func neRefVal(ref string, line int) ir.Value {
	return ir.Value{Ref: ref, Span: spanAt(line)}
}

// --- 506: Public LB without WAF ---

func Test506_FiresPublicNoWAF(t *testing.T) {
	lb := res("aws_lb", "web", map[string]ir.Value{"internal": kv(false, 3)})
	fs := (publicLBNoWAF{}).CheckAll([]ir.Resource{lb})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %q", fs[0].Severity)
	}
	if fs[0].Resource != "aws_lb.web" {
		t.Fatalf("wrong resource %q", fs[0].Resource)
	}
}

func Test506_FiresAbsentInternal(t *testing.T) {
	// internal absent = public by provider default
	lb := res("aws_alb", "web", map[string]ir.Value{})
	fs := (publicLBNoWAF{}).CheckAll([]ir.Resource{lb})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test506_InternalQuiet(t *testing.T) {
	lb := res("aws_lb", "web", map[string]ir.Value{"internal": kv(true, 3)})
	fs := (publicLBNoWAF{}).CheckAll([]ir.Resource{lb})
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test506_WAFAssociatedQuiet(t *testing.T) {
	lb := res("aws_lb", "web", map[string]ir.Value{"internal": kv(false, 3)})
	assoc := res("aws_wafv2_web_acl_association", "x", map[string]ir.Value{
		"resource_arn": neRefVal("aws_lb.web.arn", 8),
	})
	fs := (publicLBNoWAF{}).CheckAll([]ir.Resource{lb, assoc})
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test506_UnknownInternalQuiet(t *testing.T) {
	lb := res("aws_lb", "web", map[string]ir.Value{"internal": ku(3)})
	fs := (publicLBNoWAF{}).CheckAll([]ir.Resource{lb})
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test506_DeterministicOrder(t *testing.T) {
	a := res("aws_lb", "a", map[string]ir.Value{})
	b := res("aws_lb", "b", map[string]ir.Value{})
	fs := (publicLBNoWAF{}).CheckAll([]ir.Resource{b, a})
	if len(fs) != 2 || fs[0].Resource != "aws_lb.a" || fs[1].Resource != "aws_lb.b" {
		t.Fatalf("not deterministic/address-ordered: %+v", fs)
	}
}

// --- 507: Search domain outside VPC ---

func Test507_Fires(t *testing.T) {
	for _, typ := range []string{"aws_elasticsearch_domain", "aws_opensearch_domain"} {
		fs := runRule(searchOutsideVPC{}, res(typ, "d", map[string]ir.Value{}))
		if len(fs) != 1 {
			t.Fatalf("%s: got %d findings, want 1", typ, len(fs))
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("%s: wrong severity", typ)
		}
	}
}

func Test507_VPCQuiet(t *testing.T) {
	fs := runRule(searchOutsideVPC{}, res("aws_opensearch_domain", "d",
		map[string]ir.Value{"vpc_options": blks(3, blk("subnet_ids", strList(4, "s-1")))}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test507_UnknownQuiet(t *testing.T) {
	fs := runRule(searchOutsideVPC{}, res("aws_opensearch_domain", "d",
		map[string]ir.Value{"vpc_options": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 508: Redshift outside VPC ---

func Test508_Fires(t *testing.T) {
	fs := runRule(redshiftOutsideVPC{}, res("aws_redshift_cluster", "c", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test508_SubnetGroupQuiet(t *testing.T) {
	fs := runRule(redshiftOutsideVPC{}, res("aws_redshift_cluster", "c",
		map[string]ir.Value{"cluster_subnet_group_name": ks("sg-1", 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test508_UnknownQuiet(t *testing.T) {
	fs := runRule(redshiftOutsideVPC{}, res("aws_redshift_cluster", "c",
		map[string]ir.Value{"cluster_subnet_group_name": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 509: Transfer Server public ---

func Test509_Fires(t *testing.T) {
	fs := runRule(transferPublic{}, res("aws_transfer_server", "s",
		map[string]ir.Value{"endpoint_type": ks("PUBLIC", 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %q", fs[0].Severity)
	}
}

func Test509_VPCQuiet(t *testing.T) {
	fs := runRule(transferPublic{}, res("aws_transfer_server", "s",
		map[string]ir.Value{"endpoint_type": ks("VPC", 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test509_AbsentFires(t *testing.T) {
	// Absent endpoint_type: the AWS API default is PUBLIC — fail closed.
	fs := runRule(transferPublic{}, res("aws_transfer_server", "s", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].RuleID != "AEGIS-AWS-509" {
		t.Fatalf("got rule %s, want AEGIS-AWS-509", fs[0].RuleID)
	}
}

func Test509_UnknownQuiet(t *testing.T) {
	fs := runRule(transferPublic{}, res("aws_transfer_server", "s",
		map[string]ir.Value{"endpoint_type": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 510: LB listener without HTTP->HTTPS redirect ---

func Test510_Fires(t *testing.T) {
	fs := runRule(lbListenerNoRedirect{}, res("aws_lb_listener", "http",
		map[string]ir.Value{
			"port":           ir.Value{Raw: float64(80), Known: true, Span: spanAt(3)},
			"default_action": blks(4, blk("type", ks("forward", 5))),
		}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity %q", fs[0].Severity)
	}
}

func Test510_RedirectQuiet(t *testing.T) {
	fs := runRule(lbListenerNoRedirect{}, res("aws_lb_listener", "http",
		map[string]ir.Value{
			"port":           ir.Value{Raw: float64(80), Known: true, Span: spanAt(3)},
			"default_action": blks(4, blk("type", ks("redirect", 5))),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test510_Non80Quiet(t *testing.T) {
	fs := runRule(lbListenerNoRedirect{}, res("aws_lb_listener", "https",
		map[string]ir.Value{
			"port":           ir.Value{Raw: float64(443), Known: true, Span: spanAt(3)},
			"default_action": blks(4, blk("type", ks("forward", 5))),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test510_UnknownPortQuiet(t *testing.T) {
	fs := runRule(lbListenerNoRedirect{}, res("aws_lb_listener", "http",
		map[string]ir.Value{"port": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 511: SageMaker notebook not in VPC ---

func Test511_Fires(t *testing.T) {
	fs := runRule(sagemakerNoVPC{}, res("aws_sagemaker_notebook_instance", "n", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test511_SubnetQuiet(t *testing.T) {
	fs := runRule(sagemakerNoVPC{}, res("aws_sagemaker_notebook_instance", "n",
		map[string]ir.Value{"subnet_id": ks("subnet-1", 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test511_UnknownQuiet(t *testing.T) {
	fs := runRule(sagemakerNoVPC{}, res("aws_sagemaker_notebook_instance", "n",
		map[string]ir.Value{"subnet_id": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 512: CloudFront without geo restriction ---

func Test512_Fires(t *testing.T) {
	fs := runRule(cloudfrontNoGeoRestrict{}, res("aws_cloudfront_distribution", "d",
		map[string]ir.Value{
			"restrictions": blks(3,
				blk("geo_restriction", ir.Value{
					Raw:   map[string]ir.Value{"restriction_type": ks("none", 5)},
					Known: true, Span: spanAt(4),
				}),
			),
		}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity %q", fs[0].Severity)
	}
}

func Test512_WhitelistQuiet(t *testing.T) {
	fs := runRule(cloudfrontNoGeoRestrict{}, res("aws_cloudfront_distribution", "d",
		map[string]ir.Value{
			"restrictions": blks(3,
				blk("geo_restriction", ir.Value{
					Raw:   map[string]ir.Value{"restriction_type": ks("whitelist", 5)},
					Known: true, Span: spanAt(4),
				}),
			),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test512_AbsentQuiet(t *testing.T) {
	// no restrictions block at all: cannot decide per contract
	fs := runRule(cloudfrontNoGeoRestrict{}, res("aws_cloudfront_distribution", "d", map[string]ir.Value{}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test512_UnknownQuiet(t *testing.T) {
	fs := runRule(cloudfrontNoGeoRestrict{}, res("aws_cloudfront_distribution", "d",
		map[string]ir.Value{
			"restrictions": blks(3,
				blk("geo_restriction", ir.Value{
					Raw:   map[string]ir.Value{"restriction_type": ku(5)},
					Known: true, Span: spanAt(4),
				}),
			),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 513: AppSync API without WAF ---

func Test513_Fires(t *testing.T) {
	api := res("aws_appsync_graphql_api", "api", map[string]ir.Value{})
	fs := (appsyncNoWAF{}).CheckAll([]ir.Resource{api})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity %q", fs[0].Severity)
	}
}

func Test513_WAFAssociatedQuiet(t *testing.T) {
	api := res("aws_appsync_graphql_api", "api", map[string]ir.Value{})
	assoc := res("aws_wafv2_web_acl_association", "x", map[string]ir.Value{
		"resource_arn": neRefVal("aws_appsync_graphql_api.api.arn", 8),
	})
	fs := (appsyncNoWAF{}).CheckAll([]ir.Resource{api, assoc})
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test513_OtherResourceWAFQuiet(t *testing.T) {
	// WAF on a different resource must not silence this API
	api := res("aws_appsync_graphql_api", "api", map[string]ir.Value{})
	assoc := res("aws_wafv2_web_acl_association", "x", map[string]ir.Value{
		"resource_arn": neRefVal("aws_lb.web.arn", 8),
	})
	fs := (appsyncNoWAF{}).CheckAll([]ir.Resource{api, assoc})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}
