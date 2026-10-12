package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-740
// ---------------------------------------------------------------------------

func TestWafNoSampledRequestsFires(t *testing.T) {
	f := runRule(wafNoSampledRequests{},
		res("aws_wafv2_web_acl", "w", map[string]ir.Value{
			"visibility_config": blks(3, blk("sampled_requests_enabled", kv(false, 4))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-740" {
		t.Fatalf("expected 1 finding for 740, got %d", len(f))
	}
}

func TestWafNoSampledRequestsQuiet(t *testing.T) {
	f := runRule(wafNoSampledRequests{},
		res("aws_wafv2_web_acl", "w", map[string]ir.Value{
			"visibility_config": blks(3, blk("sampled_requests_enabled", kv(true, 4))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestWafNoSampledRequestsAbsentQuiet(t *testing.T) {
	f := runRule(wafNoSampledRequests{},
		res("aws_wafv2_web_acl", "w", map[string]ir.Value{}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-741
// ---------------------------------------------------------------------------

func TestLbListenerTlsOnPort80Fires(t *testing.T) {
	f := runRule(lbListenerTlsOnPort80{},
		res("aws_lb_listener", "l", map[string]ir.Value{
			"port":     intVal(80, 3),
			"protocol": ks("HTTPS", 4),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-741" {
		t.Fatalf("expected 1 finding for 741, got %d", len(f))
	}
}

func TestLbListenerTlsOnPort80Quiet(t *testing.T) {
	f := runRule(lbListenerTlsOnPort80{},
		res("aws_lb_listener", "l", map[string]ir.Value{
			"port":     intVal(443, 3),
			"protocol": ks("HTTPS", 4),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestLbListenerTlsOnPort80UnknownQuiet(t *testing.T) {
	f := runRule(lbListenerTlsOnPort80{},
		res("aws_lb_listener", "l", map[string]ir.Value{
			"port":     ku(3),
			"protocol": ks("HTTPS", 4),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-742
// ---------------------------------------------------------------------------

func TestVpcNoDnsHostnamesFires(t *testing.T) {
	f := runRule(vpcNoDnsHostnames{},
		res("aws_vpc", "v", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-742" {
		t.Fatalf("expected 1 finding for 742, got %d", len(f))
	}
}

func TestVpcNoDnsHostnamesQuiet(t *testing.T) {
	f := runRule(vpcNoDnsHostnames{},
		res("aws_vpc", "v", map[string]ir.Value{"enable_dns_hostnames": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestVpcNoDnsHostnamesUnknownQuiet(t *testing.T) {
	f := runRule(vpcNoDnsHostnames{},
		res("aws_vpc", "v", map[string]ir.Value{"enable_dns_hostnames": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-743
// ---------------------------------------------------------------------------

func TestVpcNoDnsSupportFires(t *testing.T) {
	f := runRule(vpcNoDnsSupport{},
		res("aws_vpc", "v", map[string]ir.Value{"enable_dns_support": kv(false, 3)}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-743" {
		t.Fatalf("expected 1 finding for 743, got %d", len(f))
	}
}

func TestVpcNoDnsSupportQuiet(t *testing.T) {
	f := runRule(vpcNoDnsSupport{},
		res("aws_vpc", "v", map[string]ir.Value{"enable_dns_support": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestVpcNoDnsSupportAbsentQuiet(t *testing.T) {
	// AWS provider default for enable_dns_support is true; absent must not fire.
	f := runRule(vpcNoDnsSupport{},
		res("aws_vpc", "v", map[string]ir.Value{}))
	if len(f) != 0 {
		t.Fatalf("absent: expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-744
// ---------------------------------------------------------------------------

func TestRoutePublicIgwFires(t *testing.T) {
	f := runRule(routePublicIgw{},
		res("aws_route", "r", map[string]ir.Value{
			"destination_cidr_block": ks("0.0.0.0/0", 3),
			"gateway_id":             ks("igw-0abc123", 4),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-744" {
		t.Fatalf("expected 1 finding for 744, got %d", len(f))
	}
}

func TestRoutePublicIgwQuiet(t *testing.T) {
	f := runRule(routePublicIgw{},
		res("aws_route", "r", map[string]ir.Value{
			"destination_cidr_block": ks("0.0.0.0/0", 3),
			"nat_gateway_id":         ks("nat-0abc123", 4),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestRoutePublicIgwUnknownQuiet(t *testing.T) {
	f := runRule(routePublicIgw{},
		res("aws_route", "r", map[string]ir.Value{
			"destination_cidr_block": ks("0.0.0.0/0", 3),
			"gateway_id":             ku(4),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-745
// ---------------------------------------------------------------------------

func TestDefaultSGOpenRuleFires(t *testing.T) {
	f := runRule(defaultSGOpenRule{},
		res("aws_default_security_group", "d", map[string]ir.Value{
			"ingress": blks(3, blk("cidr_blocks", strList(4, "0.0.0.0/0"))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-745" {
		t.Fatalf("expected 1 finding for 745, got %d", len(f))
	}
}

func TestDefaultSGOpenRuleQuiet(t *testing.T) {
	f := runRule(defaultSGOpenRule{},
		res("aws_default_security_group", "d", map[string]ir.Value{
			"ingress": blks(3, blk("cidr_blocks", strList(4, "10.0.0.0/8"))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestDefaultSGOpenRuleEmptyQuiet(t *testing.T) {
	f := runRule(defaultSGOpenRule{},
		res("aws_default_security_group", "d", map[string]ir.Value{}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-746
// ---------------------------------------------------------------------------

func TestDefaultNaclAllowAllFires(t *testing.T) {
	f := runRule(defaultNaclAllowAll{},
		res("aws_default_network_acl", "n", map[string]ir.Value{
			"ingress": blks(3, blk(
				"action", ks("allow", 4),
				"cidr_block", ks("0.0.0.0/0", 5),
				"protocol", ks("-1", 6),
			)),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-746" {
		t.Fatalf("expected 1 finding for 746, got %d", len(f))
	}
}

func TestDefaultNaclAllowAllQuiet(t *testing.T) {
	f := runRule(defaultNaclAllowAll{},
		res("aws_default_network_acl", "n", map[string]ir.Value{
			"ingress": blks(3, blk(
				"action", ks("deny", 4),
				"cidr_block", ks("0.0.0.0/0", 5),
				"protocol", ks("-1", 6),
			)),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-747
// ---------------------------------------------------------------------------

func TestVpcEndpointAutoAcceptFires(t *testing.T) {
	f := runRule(vpcEndpointAutoAccept{},
		res("aws_vpc_endpoint", "e", map[string]ir.Value{"auto_accept": kv(true, 3)}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-747" {
		t.Fatalf("expected 1 finding for 747, got %d", len(f))
	}
}

func TestVpcEndpointAutoAcceptQuiet(t *testing.T) {
	f := runRule(vpcEndpointAutoAccept{},
		res("aws_vpc_endpoint", "e", map[string]ir.Value{"auto_accept": kv(false, 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-748
// ---------------------------------------------------------------------------

func TestCustomerGatewayPrivateAsnFires(t *testing.T) {
	f := runRule(customerGatewayPrivateAsn{},
		res("aws_customer_gateway", "g", map[string]ir.Value{"bgp_asn": intVal(65000, 3)}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-748" {
		t.Fatalf("expected 1 finding for 748, got %d", len(f))
	}
}

func TestCustomerGatewayPrivateAsnQuiet(t *testing.T) {
	f := runRule(customerGatewayPrivateAsn{},
		res("aws_customer_gateway", "g", map[string]ir.Value{"bgp_asn": intVal(64513, 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestCustomerGatewayPrivateAsnUnknownQuiet(t *testing.T) {
	f := runRule(customerGatewayPrivateAsn{},
		res("aws_customer_gateway", "g", map[string]ir.Value{"bgp_asn": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-749
// ---------------------------------------------------------------------------

func TestRoute53WeightedNoHealthCheckFires(t *testing.T) {
	f := runRule(route53WeightedNoHealthCheck{},
		res("aws_route53_record", "r", map[string]ir.Value{
			"weighted_routing_policy": blks(3, blk("weight", intVal(100, 4))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-749" {
		t.Fatalf("expected 1 finding for 749, got %d", len(f))
	}
}

func TestRoute53WeightedNoHealthCheckQuiet(t *testing.T) {
	f := runRule(route53WeightedNoHealthCheck{},
		res("aws_route53_record", "r", map[string]ir.Value{
			"weighted_routing_policy": blks(3, blk("weight", intVal(100, 4))),
			"health_check_id":         ks("abc123", 5),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestRoute53WeightedNoHealthCheckSimpleQuiet(t *testing.T) {
	f := runRule(route53WeightedNoHealthCheck{},
		res("aws_route53_record", "r", map[string]ir.Value{
			"type": ks("A", 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-750
// ---------------------------------------------------------------------------

func TestAcmEmailValidationFires(t *testing.T) {
	f := runRule(acmEmailValidation{},
		res("aws_acm_certificate", "c", map[string]ir.Value{
			"validation_method": ks("EMAIL", 3),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-750" {
		t.Fatalf("expected 1 finding for 750, got %d", len(f))
	}
}

func TestAcmEmailValidationQuiet(t *testing.T) {
	f := runRule(acmEmailValidation{},
		res("aws_acm_certificate", "c", map[string]ir.Value{
			"validation_method": ks("DNS", 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-751
// ---------------------------------------------------------------------------

func TestApiGwRestApiPublicPolicyFires(t *testing.T) {
	f := runRule(apiGwRestApiPublicPolicy{},
		res("aws_api_gateway_rest_api", "a", map[string]ir.Value{
			"policy": ks(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke"}]}`, 3),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-751" {
		t.Fatalf("expected 1 finding for 751, got %d", len(f))
	}
}

func TestApiGwRestApiPublicPolicyQuiet(t *testing.T) {
	f := runRule(apiGwRestApiPublicPolicy{},
		res("aws_api_gateway_rest_api", "a", map[string]ir.Value{
			"policy": ks(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Condition":{"StringNotEquals":{"aws:SourceVpc":"vpc-123"}}}]}`, 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestApiGwRestApiPublicPolicyUnknownQuiet(t *testing.T) {
	f := runRule(apiGwRestApiPublicPolicy{},
		res("aws_api_gateway_rest_api", "a", map[string]ir.Value{"policy": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-752
// ---------------------------------------------------------------------------

func TestCfNoLoggingFires(t *testing.T) {
	f := runRule(cfNoLogging{},
		res("aws_cloudfront_distribution", "d", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-752" {
		t.Fatalf("expected 1 finding for 752, got %d", len(f))
	}
}

func TestCfNoLoggingQuiet(t *testing.T) {
	f := runRule(cfNoLogging{},
		res("aws_cloudfront_distribution", "d", map[string]ir.Value{
			"logging_config": blks(3, blk("bucket", ks("logs.s3.amazonaws.com", 4))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-753
// ---------------------------------------------------------------------------

func TestCfS3NoOACFires(t *testing.T) {
	f := runRule(cfS3NoOAC{},
		res("aws_cloudfront_distribution", "d", map[string]ir.Value{
			"origin": blks(3, blk(
				"domain_name", ks("mybucket.s3.amazonaws.com", 4),
				"s3_origin_config", blks(5, blk()),
			)),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-753" {
		t.Fatalf("expected 1 finding for 753, got %d", len(f))
	}
}

func TestCfS3NoOACQuiet(t *testing.T) {
	f := runRule(cfS3NoOAC{},
		res("aws_cloudfront_distribution", "d", map[string]ir.Value{
			"origin": blks(3, blk(
				"domain_name", ks("mybucket.s3.amazonaws.com", 4),
				"origin_access_control_id", ks("oac-123", 5),
				"s3_origin_config", blks(6, blk()),
			)),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestCfS3NoOACLegacyOAIQuiet(t *testing.T) {
	// Legacy OAI is rule 825's territory, not 753's.
	f := runRule(cfS3NoOAC{},
		res("aws_cloudfront_distribution", "d", map[string]ir.Value{
			"origin": blks(3, blk(
				"domain_name", ks("mybucket.s3.amazonaws.com", 4),
				"s3_origin_config", blks(5, blk("origin_access_identity", ks("origin-access-identity/cloudfront/E123", 6))),
			)),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-754
// ---------------------------------------------------------------------------

func TestCfWeakViewerCertTlsFires(t *testing.T) {
	f := runRule(cfWeakViewerCertTls{},
		res("aws_cloudfront_distribution", "d", map[string]ir.Value{
			"viewer_certificate": blks(3, blk("minimum_protocol_version", ks("TLSv1", 4))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-754" {
		t.Fatalf("expected 1 finding for 754, got %d", len(f))
	}
}

func TestCfWeakViewerCertTlsQuiet(t *testing.T) {
	f := runRule(cfWeakViewerCertTls{},
		res("aws_cloudfront_distribution", "d", map[string]ir.Value{
			"viewer_certificate": blks(3, blk("minimum_protocol_version", ks("TLSv1.2_2021", 4))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-755
// ---------------------------------------------------------------------------

func TestApiGwStageNoXrayFires(t *testing.T) {
	f := runRule(apiGwStageNoXray{},
		res("aws_api_gateway_stage", "s", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-755" {
		t.Fatalf("expected 1 finding for 755, got %d", len(f))
	}
}

func TestApiGwStageNoXrayQuiet(t *testing.T) {
	f := runRule(apiGwStageNoXray{},
		res("aws_api_gateway_stage", "s", map[string]ir.Value{"xray_tracing_enabled": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestApiGwStageNoXrayUnknownQuiet(t *testing.T) {
	f := runRule(apiGwStageNoXray{},
		res("aws_api_gateway_stage", "s", map[string]ir.Value{"xray_tracing_enabled": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-756
// ---------------------------------------------------------------------------

func TestApiGwStageNoClientCertFires(t *testing.T) {
	f := runRule(apiGwStageNoClientCert{},
		res("aws_api_gateway_stage", "s", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-756" {
		t.Fatalf("expected 1 finding for 756, got %d", len(f))
	}
}

func TestApiGwStageNoClientCertQuiet(t *testing.T) {
	f := runRule(apiGwStageNoClientCert{},
		res("aws_api_gateway_stage", "s", map[string]ir.Value{"client_certificate_id": ks("abc123", 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-757
// ---------------------------------------------------------------------------

func TestApiGwMethodNoThrottlingFires(t *testing.T) {
	f := runRule(apiGwMethodNoThrottling{},
		res("aws_api_gateway_method_settings", "m", map[string]ir.Value{
			"settings": blks(3, blk("metrics_enabled", kv(true, 4))),
		}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-757" {
		t.Fatalf("expected 1 finding for 757, got %d", len(f))
	}
}

func TestApiGwMethodNoThrottlingQuiet(t *testing.T) {
	f := runRule(apiGwMethodNoThrottling{},
		res("aws_api_gateway_method_settings", "m", map[string]ir.Value{
			"settings": blks(3, blk("throttling_burst_limit", intVal(100, 4))),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestApiGwMethodNoThrottlingNoSettingsQuiet(t *testing.T) {
	f := runRule(apiGwMethodNoThrottling{},
		res("aws_api_gateway_method_settings", "m", map[string]ir.Value{}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-758
// ---------------------------------------------------------------------------

func TestApiGwDeploymentNoDescFires(t *testing.T) {
	f := runRule(apiGwDeploymentNoDesc{},
		res("aws_api_gateway_deployment", "d", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-758" {
		t.Fatalf("expected 1 finding for 758, got %d", len(f))
	}
}

func TestApiGwDeploymentNoDescQuiet(t *testing.T) {
	f := runRule(apiGwDeploymentNoDesc{},
		res("aws_api_gateway_deployment", "d", map[string]ir.Value{"description": ks("add v2 endpoints", 3)}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-759
// ---------------------------------------------------------------------------

func TestNfwPolicyChangeProtectionFires(t *testing.T) {
	f := runRule(nfwPolicyChangeProtection{},
		res("aws_networkfirewall_firewall", "f", map[string]ir.Value{}))
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-759" {
		t.Fatalf("expected 1 finding for 759, got %d", len(f))
	}
}

func TestNfwPolicyChangeProtectionQuiet(t *testing.T) {
	f := runRule(nfwPolicyChangeProtection{},
		res("aws_networkfirewall_firewall", "f", map[string]ir.Value{
			"firewall_policy_change_protection": kv(true, 3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestNfwPolicyChangeProtectionUnknownQuiet(t *testing.T) {
	f := runRule(nfwPolicyChangeProtection{},
		res("aws_networkfirewall_firewall", "f", map[string]ir.Value{
			"firewall_policy_change_protection": ku(3),
		}))
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}
