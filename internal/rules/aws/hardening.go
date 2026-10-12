package aws

import (
	"strings"

	"aegis/internal/ir"
)

// HardeningRules returns the Tier 5 hardening rules (AEGIS-AWS-528-533),
// in ID order. These close Checkov parity gaps around Redshift, CloudFront,
// WAF Log4j protection, SageMaker IMDS, and default security groups.
func HardeningRules() []ir.Rule {
	return []ir.Rule{
		redshiftNoEnhancedVPCRouting{}, // AEGIS-AWS-528
		cloudfrontDefaultCert{},        // AEGIS-AWS-529
		wafNoLog4jRule{},               // AEGIS-AWS-530
		cloudfrontWAFNoLog4jAMR{},      // AEGIS-AWS-531
		sagemakerIMDSv1{},              // AEGIS-AWS-532
		defaultSGOpen{},                // AEGIS-AWS-533
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-528: Redshift cluster without enhanced VPC routing (Low)
// ---------------------------------------------------------------------------

type redshiftNoEnhancedVPCRouting struct{}

func (redshiftNoEnhancedVPCRouting) ID() string { return "AEGIS-AWS-528" }
func (redshiftNoEnhancedVPCRouting) Title() string {
	return "Redshift cluster without enhanced VPC routing"
}
func (redshiftNoEnhancedVPCRouting) Description() string {
	return "Enhanced VPC routing forces all COPY/UNLOAD traffic between the " +
		"Redshift cluster and data sources through the VPC, so VPC security " +
		"groups, network ACLs and flow logs apply. It defaults to false; an " +
		"absent attribute is therefore treated as disabled."
}
func (redshiftNoEnhancedVPCRouting) Severity() ir.Severity { return ir.SeverityLow }

func (redshiftNoEnhancedVPCRouting) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}

func (redshiftNoEnhancedVPCRouting) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "enhanced_vpc_routing")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil // explicitly enabled
	}
	actual := "absent"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-528",
		Title:       (redshiftNoEnhancedVPCRouting{}).Title(),
		Description: (redshiftNoEnhancedVPCRouting{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enhanced_vpc_routing",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "enhanced_vpc_routing = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-529: CloudFront distribution using the default certificate (Low)
// ---------------------------------------------------------------------------

type cloudfrontDefaultCert struct{}

func (cloudfrontDefaultCert) ID() string { return "AEGIS-AWS-529" }
func (cloudfrontDefaultCert) Title() string {
	return "CloudFront distribution without custom SSL certificate"
}
func (cloudfrontDefaultCert) Description() string {
	return "Distributions using the CloudFront default certificate cannot " +
		"serve a custom domain over HTTPS with a proper certificate. Use a " +
		"custom ACM certificate in viewer_certificate instead."
}
func (cloudfrontDefaultCert) Severity() ir.Severity { return ir.SeverityLow }

func (cloudfrontDefaultCert) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

func (cloudfrontDefaultCert) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "viewer_certificate")
	if !present || !known || len(blks) == 0 {
		return nil // no viewer_certificate block: cannot decide
	}
	vc := blks[0]
	v, ok := vc["cloudfront_default_certificate"]
	if !ok {
		return nil // attribute absent: cannot decide
	}
	b, kok := v.AsBool()
	if !kok {
		return nil // unresolved: cannot decide
	}
	if !b {
		return nil // custom certificate in use
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-529",
		Title:       (cloudfrontDefaultCert{}).Title(),
		Description: (cloudfrontDefaultCert{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "viewer_certificate.cloudfront_default_certificate",
			Span:      evidenceSpan(v.Span, r.Span),
			Actual:    "true",
			Expected:  "custom ACM certificate (cloudfront_default_certificate = false)",
		},
	}}
}

// knownBadInputsGroup is the AWS managed rule group that blocks Log4Shell
// and other known-bad input patterns.
const knownBadInputsGroup = "AWSManagedRulesKnownBadInputsRuleSet"

// wafHasKnownBadInputs reports whether any rule block in the web ACL
// references the AWSManagedRulesKnownBadInputsRuleSet managed rule group.
// It walks rule -> statement -> managed_rule_group_statement -> name.
func wafHasKnownBadInputs(r ir.Resource) bool {
	rules, _, present, known := getBlocks(r, "rule")
	if !present || !known {
		return false
	}
	for _, rule := range rules {
		stmts := blockList(rule, "statement")
		for _, st := range stmts {
			groups := blockList(st, "managed_rule_group_statement")
			for _, g := range groups {
				name, _, ok, kok := blockString(g, "name")
				if ok && kok && strings.EqualFold(name, knownBadInputsGroup) {
					return true
				}
			}
		}
	}
	return false
}

// wafRulesPresent reports whether the web ACL has any resolvable rule blocks.
func wafRulesPresent(r ir.Resource) bool {
	_, _, present, known := getBlocks(r, "rule")
	return present && known
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-530: WAF web ACL without Log4j protection (Low)
// ---------------------------------------------------------------------------

type wafNoLog4jRule struct{}

func (wafNoLog4jRule) ID() string { return "AEGIS-AWS-530" }
func (wafNoLog4jRule) Title() string {
	return "WAF web ACL without Log4j protection rule"
}
func (wafNoLog4jRule) Description() string {
	return "Web ACLs should include the AWSManagedRulesKnownBadInputsRuleSet " +
		"managed rule group, which blocks Log4Shell (CVE-2021-44228) and other " +
		"known-bad input payloads. Absent or unresolved rules cannot be " +
		"evaluated and yield no finding."
}
func (wafNoLog4jRule) Severity() ir.Severity { return ir.SeverityLow }

func (wafNoLog4jRule) AppliesTo(resType string) bool {
	return resType == "aws_wafv2_web_acl"
}

func (wafNoLog4jRule) Check(r ir.Resource) []ir.Finding {
	if !wafRulesPresent(r) {
		return nil // no resolvable rules: cannot decide
	}
	if wafHasKnownBadInputs(r) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-530",
		Title:       (wafNoLog4jRule{}).Title(),
		Description: (wafNoLog4jRule{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "rule",
			Span:      r.Span,
			Actual:    "no AWSManagedRulesKnownBadInputsRuleSet managed rule group",
			Expected:  "managed_rule_group_statement with name = \"AWSManagedRulesKnownBadInputsRuleSet\"",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-531: CloudFront-scoped WAF web ACL without Log4j AMR (Low)
// ---------------------------------------------------------------------------

type cloudfrontWAFNoLog4jAMR struct{}

func (cloudfrontWAFNoLog4jAMR) ID() string { return "AEGIS-AWS-531" }
func (cloudfrontWAFNoLog4jAMR) Title() string {
	return "CloudFront WAF web ACL without Log4j AWS managed rule"
}
func (cloudfrontWAFNoLog4jAMR) Description() string {
	return "CloudFront-scoped web ACLs (scope = CLOUDFRONT) protect " +
		"internet-facing distributions and must include the " +
		"AWSManagedRulesKnownBadInputsRuleSet managed rule group for " +
		"Log4Shell protection. Only web ACLs with a known CLOUDFRONT scope " +
		"are evaluated."
}
func (cloudfrontWAFNoLog4jAMR) Severity() ir.Severity { return ir.SeverityLow }

func (cloudfrontWAFNoLog4jAMR) AppliesTo(resType string) bool {
	return resType == "aws_wafv2_web_acl"
}

func (cloudfrontWAFNoLog4jAMR) Check(r ir.Resource) []ir.Finding {
	scope, _, present, known := getString(r, "scope")
	if !present || !known {
		return nil // scope unknown: cannot decide
	}
	if !strings.EqualFold(scope, "CLOUDFRONT") {
		return nil // not a CloudFront web ACL
	}
	if !wafRulesPresent(r) {
		return nil // no resolvable rules: cannot decide
	}
	if wafHasKnownBadInputs(r) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-531",
		Title:       (cloudfrontWAFNoLog4jAMR{}).Title(),
		Description: (cloudfrontWAFNoLog4jAMR{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "rule",
			Span:      r.Span,
			Actual:    "CloudFront web ACL without AWSManagedRulesKnownBadInputsRuleSet",
			Expected:  "managed_rule_group_statement with name = \"AWSManagedRulesKnownBadInputsRuleSet\"",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-532: SageMaker notebook instance allows IMDSv1 (Medium)
// ---------------------------------------------------------------------------

type sagemakerIMDSv1 struct{}

func (sagemakerIMDSv1) ID() string { return "AEGIS-AWS-532" }
func (sagemakerIMDSv1) Title() string {
	return "SageMaker notebook instance allows IMDSv1"
}
func (sagemakerIMDSv1) Description() string {
	return "SageMaker notebook instances should require IMDSv2 " +
		"(minimum_instance_metadata_service_version = 2) to protect against " +
		"SSRF credential theft. The metadata service configuration defaults " +
		"to IMDSv1, so an absent block is treated as vulnerable."
}
func (sagemakerIMDSv1) Severity() ir.Severity { return ir.SeverityMedium }

func (sagemakerIMDSv1) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_notebook_instance"
}

func (sagemakerIMDSv1) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "instance_metadata_service_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	fire := false
	actual := "absent"
	if !present || len(blks) == 0 {
		fire = true // insecure default: IMDSv1 allowed
	} else {
		cfg := blks[0]
		v, ok := cfg["minimum_instance_metadata_service_version"]
		if !ok {
			fire = true // version not pinned: IMDSv1 still allowed
			actual = "minimum_instance_metadata_service_version absent"
		} else if s, kok := v.AsString(); !kok {
			return nil // unresolved: cannot decide
		} else if s != "2" {
			fire = true
			actual = s
		}
	}
	if !fire {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-532",
		Title:       (sagemakerIMDSv1{}).Title(),
		Description: (sagemakerIMDSv1{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "instance_metadata_service_configuration.minimum_instance_metadata_service_version",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "minimum_instance_metadata_service_version = 2",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-533: Default security group allows all traffic (Medium)
// ---------------------------------------------------------------------------

type defaultSGOpen struct{}

func (defaultSGOpen) ID() string { return "AEGIS-AWS-533" }
func (defaultSGOpen) Title() string {
	return "Default security group allows traffic from anywhere"
}
func (defaultSGOpen) Description() string {
	return "The default security group of a VPC should not allow ingress " +
		"or egress to/from 0.0.0.0/0. Default groups are attached " +
		"implicitly, so overly permissive rules expose every associated " +
		"resource. Applies only to aws_default_security_group, never to " +
		"regular aws_security_group resources."
}
func (defaultSGOpen) Severity() ir.Severity { return ir.SeverityMedium }

func (defaultSGOpen) AppliesTo(resType string) bool {
	return resType == "aws_default_security_group"
}

func (defaultSGOpen) Check(r ir.Resource) []ir.Finding {
	out := checkSGBlocks(r, "ingress", defaultSGOpen{})
	out = append(out, checkSGBlocks(r, "egress", defaultSGOpen{})...)
	return out
}
