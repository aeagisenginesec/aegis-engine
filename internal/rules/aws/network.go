package aws

import (
	"strings"

	"aegis/internal/ir"
)

// Network & edge rules (AEGIS-AWS-323..332): load balancers, CloudFront,
// API Gateway, and network ACLs.

// NetworkRules returns the network & edge rule pack in ID order.
func NetworkRules() []ir.Rule {
	return []ir.Rule{
		lbNoDeletionProtection{},  // AEGIS-AWS-323
		lbListenerWeakTLS{},       // AEGIS-AWS-324
		cloudfrontAllowsHTTP{},    // AEGIS-AWS-325
		apiGwDomainWeakTLS{},      // AEGIS-AWS-326
		apiGwStageNoAccessLog{},   // AEGIS-AWS-327
		naclOpenIngress{},         // AEGIS-AWS-328
		lbTargetGroupPlainHTTP{},  // AEGIS-AWS-329
		cloudfrontNoWAF{},         // AEGIS-AWS-330
		naclRuleOpenIngress{},     // AEGIS-AWS-331
		apiGwV2StageNoAccessLog{}, // AEGIS-AWS-332
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-323: Load balancer without deletion protection
// ---------------------------------------------------------------------------

type lbNoDeletionProtection struct{}

func (lbNoDeletionProtection) ID() string { return "AEGIS-AWS-323" }
func (lbNoDeletionProtection) Title() string {
	return "Load balancer without deletion protection"
}
func (lbNoDeletionProtection) Description() string {
	return "Without enable_deletion_protection, a load balancer can be " +
		"destroyed by a single API call or Terraform change, taking the " +
		"service offline. The provider default is disabled."
}
func (lbNoDeletionProtection) Severity() ir.Severity { return ir.SeverityMedium }

func (lbNoDeletionProtection) AppliesTo(resType string) bool {
	return resType == "aws_lb" || resType == "aws_alb"
}

func (lbNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	prot, span, present, known := getBool(r, "enable_deletion_protection")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && prot {
		return nil // protected
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-323",
		Title:       (lbNoDeletionProtection{}).Title(),
		Description: (lbNoDeletionProtection{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enable_deletion_protection",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "enable_deletion_protection = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-324: Load balancer listener with weak TLS policy
// ---------------------------------------------------------------------------

type lbListenerWeakTLS struct{}

func (lbListenerWeakTLS) ID() string { return "AEGIS-AWS-324" }
func (lbListenerWeakTLS) Title() string {
	return "Load balancer listener with weak TLS policy"
}
func (lbListenerWeakTLS) Description() string {
	return "A TLS listener using a pre-TLS-1.2 security policy (e.g. " +
		"ELBSecurityPolicy-2016-08) negotiates weak cipher suites. Use a " +
		"TLS 1.2+ policy such as ELBSecurityPolicy-TLS13-1-2-2021-06."
}
func (lbListenerWeakTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (lbListenerWeakTLS) AppliesTo(resType string) bool {
	return resType == "aws_lb_listener" || resType == "aws_alb_listener"
}

// tls12Plus reports whether a policy name indicates TLS 1.2 or better.
// Separators are normalized so TLS13-1-2, TLS-1-2, TLS1.2, and FS-1-2
// (forward-secrecy TLS 1.2 suites) all match.
func tls12Plus(policy string) bool {
	p := strings.NewReplacer("-", "", ".", "", "_", "").Replace(strings.ToUpper(policy))
	return strings.Contains(p, "TLS12") ||
		strings.Contains(p, "TLS13") ||
		strings.Contains(p, "FS12")
}

func (lbListenerWeakTLS) Check(r ir.Resource) []ir.Finding {
	proto, _, ppresent, pknown := getString(r, "protocol")
	if !ppresent || !pknown {
		return nil // not provably a TLS listener
	}
	p := strings.ToUpper(strings.TrimSpace(proto))
	if p != "HTTPS" && p != "TLS" {
		return nil // plain HTTP is rule 202's territory
	}
	policy, span, present, known := getString(r, "ssl_policy")
	if !present {
		// Optional on a TLS listener; AWS applies ELBSecurityPolicy-2016-08,
		// which negotiates pre-TLS-1.2 cipher suites (weak by this rule's
		// own definition).
		return absentInsecureDefault(lbListenerWeakTLS{}, r,
			"ssl_policy", "absent (provider default: ELBSecurityPolicy-2016-08)",
			"a TLS 1.2+ policy (e.g. ELBSecurityPolicy-TLS13-1-2-2021-06)")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if tls12Plus(policy) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-324",
		Title:       (lbListenerWeakTLS{}).Title(),
		Description: (lbListenerWeakTLS{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "ssl_policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    policy,
			Expected:  "a TLS 1.2+ policy (e.g. ELBSecurityPolicy-TLS13-1-2-2021-06)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-325: CloudFront distribution allows HTTP
// ---------------------------------------------------------------------------

type cloudfrontAllowsHTTP struct{}

func (cloudfrontAllowsHTTP) ID() string { return "AEGIS-AWS-325" }
func (cloudfrontAllowsHTTP) Title() string {
	return "CloudFront distribution allows HTTP"
}
func (cloudfrontAllowsHTTP) Description() string {
	return "A cache behavior with viewer_protocol_policy = \"allow-all\" " +
		"serves content over unencrypted HTTP. Use \"https-only\" or " +
		"\"redirect-to-https\"."
}
func (cloudfrontAllowsHTTP) Severity() ir.Severity { return ir.SeverityHigh }

func (cloudfrontAllowsHTTP) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

// firstHTTPBehavior returns the first cache behavior block whose
// viewer_protocol_policy is known "allow-all", or nil.
func firstHTTPBehavior(r ir.Resource) (map[string]ir.Value, ir.Span, string, bool) {
	for _, attr := range []string{"default_cache_behavior", "ordered_cache_behavior"} {
		blks, span, present, known := getBlocks(r, attr)
		if !present || !known {
			continue // absent or unresolved: cannot decide
		}
		for _, b := range blks {
			pol, pspan, ppresent, pknown := blockString(b, "viewer_protocol_policy")
			if !ppresent || !pknown {
				continue // absent or unresolved: cannot decide
			}
			if strings.EqualFold(strings.TrimSpace(pol), "allow-all") {
				return b, evidenceSpan(pspan, span), attr, true
			}
		}
	}
	return nil, ir.Span{}, "", false
}

func (cloudfrontAllowsHTTP) Check(r ir.Resource) []ir.Finding {
	_, span, attr, found := firstHTTPBehavior(r)
	if !found {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-325",
		Title:       (cloudfrontAllowsHTTP{}).Title(),
		Description: (cloudfrontAllowsHTTP{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr + ".viewer_protocol_policy",
			Span:      span,
			Actual:    "allow-all",
			Expected:  "https-only or redirect-to-https",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-326: API Gateway custom domain with weak TLS
// ---------------------------------------------------------------------------

type apiGwDomainWeakTLS struct{}

func (apiGwDomainWeakTLS) ID() string { return "AEGIS-AWS-326" }
func (apiGwDomainWeakTLS) Title() string {
	return "API Gateway custom domain with weak TLS"
}
func (apiGwDomainWeakTLS) Description() string {
	return "A custom domain name with security_policy below TLS_1_2 (e.g. " +
		"TLS_1_0) negotiates weak cipher suites. The modern provider default " +
		"is TLS_1_2."
}
func (apiGwDomainWeakTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (apiGwDomainWeakTLS) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_domain_name"
}

func (apiGwDomainWeakTLS) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "security_policy")
	if !present {
		return nil // modern provider default is TLS_1_2
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(pol), "TLS_1_2") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-326",
		Title:       (apiGwDomainWeakTLS{}).Title(),
		Description: (apiGwDomainWeakTLS{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "security_policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    pol,
			Expected:  "TLS_1_2",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-327: API Gateway stage without access logging
// ---------------------------------------------------------------------------

type apiGwStageNoAccessLog struct{}

func (apiGwStageNoAccessLog) ID() string { return "AEGIS-AWS-327" }
func (apiGwStageNoAccessLog) Title() string {
	return "API Gateway stage without access logging"
}
func (apiGwStageNoAccessLog) Description() string {
	return "A stage without an access_log_settings block leaves no audit " +
		"trail of API invocations, hampering incident response and anomaly " +
		"detection."
}
func (apiGwStageNoAccessLog) Severity() ir.Severity { return ir.SeverityMedium }

func (apiGwStageNoAccessLog) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_stage"
}

func (apiGwStageNoAccessLog) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "access_log_settings")
	if present {
		if !known {
			return nil // unresolved block: cannot decide
		}
		return nil // block declared
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-327",
		Title:       (apiGwStageNoAccessLog{}).Title(),
		Description: (apiGwStageNoAccessLog{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "access_log_settings",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent",
			Expected:  "access_log_settings { destination_arn = ... }",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-328: Network ACL with open ingress (inline blocks)
// ---------------------------------------------------------------------------

type naclOpenIngress struct{}

func (naclOpenIngress) ID() string { return "AEGIS-AWS-328" }
func (naclOpenIngress) Title() string {
	return "Network ACL with open ingress"
}
func (naclOpenIngress) Description() string {
	return "An inline NACL ingress rule allowing 0.0.0.0/0 exposes the " +
		"subnet to the internet at the stateless network layer. NACLs are a " +
		"coarse control; restrict ingress to known ranges."
}
func (naclOpenIngress) Severity() ir.Severity { return ir.SeverityMedium }

func (naclOpenIngress) AppliesTo(resType string) bool {
	return resType == "aws_network_acl"
}

// naclBlockOpenAllow reports whether a NACL rule block provably allows the
// world. cidrKey is "cidr_block" (IPv4); actionKey is "action" for inline
// blocks and "rule_action" for standalone rule resources.
func naclBlockOpenAllow(b map[string]ir.Value, cidrKey, actionKey string) bool {
	cidr, _, cpresent, cknown := blockString(b, cidrKey)
	if !cpresent || !cknown {
		return false // unresolved: cannot prove
	}
	if strings.TrimSpace(cidr) != "0.0.0.0/0" {
		return false
	}
	action, _, apresent, aknown := blockString(b, actionKey)
	if !apresent || !aknown {
		return false // unresolved: cannot prove
	}
	return strings.EqualFold(strings.TrimSpace(action), "allow")
}

func (naclOpenIngress) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "ingress")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	hit := false
	for _, b := range blks {
		if naclBlockOpenAllow(b, "cidr_block", "action") {
			hit = true
			break
		}
	}
	if !hit {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-328",
		Title:       (naclOpenIngress{}).Title(),
		Description: (naclOpenIngress{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "ingress.cidr_block",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "0.0.0.0/0 (allow)",
			Expected:  "restricted ingress CIDR ranges",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-329: Load balancer target group uses plain HTTP
// ---------------------------------------------------------------------------

type lbTargetGroupPlainHTTP struct{}

func (lbTargetGroupPlainHTTP) ID() string { return "AEGIS-AWS-329" }
func (lbTargetGroupPlainHTTP) Title() string {
	return "Load balancer target group uses plain HTTP"
}
func (lbTargetGroupPlainHTTP) Description() string {
	return "A target group with protocol = \"HTTP\" forwards traffic to " +
		"targets unencrypted, exposing internal traffic on the network. " +
		"Use HTTPS for backend connections."
}
func (lbTargetGroupPlainHTTP) Severity() ir.Severity { return ir.SeverityHigh }

func (lbTargetGroupPlainHTTP) AppliesTo(resType string) bool {
	return resType == "aws_lb_target_group"
}

func (lbTargetGroupPlainHTTP) Check(r ir.Resource) []ir.Finding {
	proto, span, present, known := getString(r, "protocol")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(proto), "HTTP") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-329",
		Title:       (lbTargetGroupPlainHTTP{}).Title(),
		Description: (lbTargetGroupPlainHTTP{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "protocol",
			Span:      evidenceSpan(span, r.Span),
			Actual:    proto,
			Expected:  "HTTPS",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-330: CloudFront distribution without WAF
// ---------------------------------------------------------------------------

type cloudfrontNoWAF struct{}

func (cloudfrontNoWAF) ID() string { return "AEGIS-AWS-330" }
func (cloudfrontNoWAF) Title() string {
	return "CloudFront distribution without WAF"
}
func (cloudfrontNoWAF) Description() string {
	return "A distribution with no web_acl_id attached has no WAFv2 " +
		"protection against common web exploits and bots at the edge."
}
func (cloudfrontNoWAF) Severity() ir.Severity { return ir.SeverityMedium }

func (cloudfrontNoWAF) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

func (cloudfrontNoWAF) Check(r ir.Resource) []ir.Finding {
	acl, span, present, known := getString(r, "web_acl_id")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(acl) != "" {
		return nil // WAF attached
	}
	actual := "absent"
	if present {
		actual = "empty string"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-330",
		Title:       (cloudfrontNoWAF{}).Title(),
		Description: (cloudfrontNoWAF{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "web_acl_id",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "a WAFv2 web ACL ID",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-331: Network ACL rule (standalone) with open ingress
// ---------------------------------------------------------------------------

type naclRuleOpenIngress struct{}

func (naclRuleOpenIngress) ID() string { return "AEGIS-AWS-331" }
func (naclRuleOpenIngress) Title() string {
	return "Network ACL rule with open ingress"
}
func (naclRuleOpenIngress) Description() string {
	return "A standalone aws_network_acl_rule allowing 0.0.0.0/0 ingress " +
		"exposes the subnet to the internet at the stateless network layer. " +
		"Restrict ingress to known ranges."
}
func (naclRuleOpenIngress) Severity() ir.Severity { return ir.SeverityMedium }

func (naclRuleOpenIngress) AppliesTo(resType string) bool {
	return resType == "aws_network_acl_rule"
}

func (naclRuleOpenIngress) Check(r ir.Resource) []ir.Finding {
	egress, _, epresent, eknown := getBool(r, "egress")
	if epresent && !eknown {
		return nil // unresolved: cannot tell ingress from egress
	}
	if epresent && egress {
		return nil // egress rule: out of scope
	}
	cidr, span, cpresent, cknown := getString(r, "cidr_block")
	if !cpresent || !cknown {
		return nil // unresolved: cannot prove
	}
	if strings.TrimSpace(cidr) != "0.0.0.0/0" {
		return nil
	}
	action, _, apresent, aknown := getString(r, "rule_action")
	if !apresent || !aknown {
		return nil // unresolved: cannot prove
	}
	if !strings.EqualFold(strings.TrimSpace(action), "allow") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-331",
		Title:       (naclRuleOpenIngress{}).Title(),
		Description: (naclRuleOpenIngress{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "cidr_block",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "0.0.0.0/0 (allow, ingress)",
			Expected:  "restricted ingress CIDR ranges",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-332: API Gateway v2 stage without access logging
// ---------------------------------------------------------------------------

type apiGwV2StageNoAccessLog struct{}

func (apiGwV2StageNoAccessLog) ID() string { return "AEGIS-AWS-332" }
func (apiGwV2StageNoAccessLog) Title() string {
	return "API Gateway v2 stage without access logging"
}
func (apiGwV2StageNoAccessLog) Description() string {
	return "A v2 (HTTP/WebSocket) stage without an access_log_settings block " +
		"leaves no audit trail of API invocations, hampering incident " +
		"response and anomaly detection."
}
func (apiGwV2StageNoAccessLog) Severity() ir.Severity { return ir.SeverityMedium }

func (apiGwV2StageNoAccessLog) AppliesTo(resType string) bool {
	return resType == "aws_apigatewayv2_stage"
}

func (apiGwV2StageNoAccessLog) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "access_log_settings")
	if present {
		if !known {
			return nil // unresolved block: cannot decide
		}
		return nil // block declared
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-332",
		Title:       (apiGwV2StageNoAccessLog{}).Title(),
		Description: (apiGwV2StageNoAccessLog{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "access_log_settings",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent",
			Expected:  "access_log_settings { destination_arn = ... }",
		},
	}}
}
