package aws

import (
	"sort"
	"strings"

	"aegis/internal/ir"
)

// Network exposure & access control rules (AEGIS-AWS-506..513): public
// load balancers and APIs without WAF, services deployed outside a VPC,
// plain-HTTP listeners, and missing geo restrictions.

// NetworkExposureRules returns the network exposure rule pack in ID order.
func NetworkExposureRules() []ir.Rule {
	return []ir.Rule{
		publicLBNoWAF{},           // AEGIS-AWS-506
		searchOutsideVPC{},        // AEGIS-AWS-507
		redshiftOutsideVPC{},      // AEGIS-AWS-508
		transferPublic{},          // AEGIS-AWS-509
		lbListenerNoRedirect{},    // AEGIS-AWS-510
		sagemakerNoVPC{},          // AEGIS-AWS-511
		cloudfrontNoGeoRestrict{}, // AEGIS-AWS-512
		appsyncNoWAF{},            // AEGIS-AWS-513
	}
}

// wafProtectedAddrs collects Terraform addresses (e.g. "aws_lb.web") that
// have an aws_wafv2_web_acl_association whose resource_arn references them.
// Matching is done on unresolved references (Ref like "aws_lb.web.arn");
// a known literal ARN string cannot be correlated to a resource and is
// ignored. Deterministic: the set is order-independent.
func wafProtectedAddrs(resources []ir.Resource) map[string]bool {
	out := map[string]bool{}
	for _, r := range resources {
		if r.Type != "aws_wafv2_web_acl_association" {
			continue
		}
		v, ok := r.Attr("resource_arn")
		if !ok {
			continue
		}
		// Refs carry Known=false by IR contract; match on the Ref path.
		if v.IsRef() {
			parts := strings.Split(v.Ref, ".")
			if len(parts) >= 2 {
				out[parts[0]+"."+parts[1]] = true
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-506: Public load balancer without WAF
// ---------------------------------------------------------------------------

type publicLBNoWAF struct{}

func (publicLBNoWAF) ID() string { return "AEGIS-AWS-506" }
func (publicLBNoWAF) Title() string {
	return "Public load balancer without WAF"
}
func (publicLBNoWAF) Description() string {
	return "An internet-facing load balancer with no WAFv2 web ACL " +
		"association is exposed to common web exploits, bots, and " +
		"application-layer DDoS with no managed filtering in front of it."
}
func (publicLBNoWAF) Severity() ir.Severity { return ir.SeverityHigh }

func (publicLBNoWAF) AppliesTo(resType string) bool {
	return resType == "aws_lb" || resType == "aws_alb"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (publicLBNoWAF) Check(ir.Resource) []ir.Finding { return nil }

func (publicLBNoWAF) CheckAll(resources []ir.Resource) []ir.Finding {
	protected := wafProtectedAddrs(resources)
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "aws_lb" && r.Type != "aws_alb" {
			continue
		}
		internal, span, present, known := getBool(r, "internal")
		if present && !known {
			continue // unresolved: cannot decide
		}
		if present && internal {
			continue // internal LB: not internet-facing
		}
		if protected[r.Address()] {
			continue // WAF associated
		}
		actual := "absent (provider default: internet-facing)"
		if present {
			actual = "false"
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-506",
			Title:       (publicLBNoWAF{}).Title(),
			Description: (publicLBNoWAF{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "internal",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "internal = true, or an aws_wafv2_web_acl_association on this load balancer",
			},
		})
	}
	return out
}

var _ ir.CrossResourceRule = publicLBNoWAF{}

// ---------------------------------------------------------------------------
// AEGIS-AWS-507: Elasticsearch/OpenSearch domain outside VPC
// ---------------------------------------------------------------------------

type searchOutsideVPC struct{}

func (searchOutsideVPC) ID() string { return "AEGIS-AWS-507" }
func (searchOutsideVPC) Title() string {
	return "Search domain outside VPC"
}
func (searchOutsideVPC) Description() string {
	return "An Elasticsearch or OpenSearch domain without vpc_options is " +
		"deployed with a public endpoint, exposing cluster APIs to the " +
		"internet instead of keeping traffic inside the VPC."
}
func (searchOutsideVPC) Severity() ir.Severity { return ir.SeverityHigh }

func (searchOutsideVPC) AppliesTo(resType string) bool {
	return resType == "aws_elasticsearch_domain" || resType == "aws_opensearch_domain"
}

func (searchOutsideVPC) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "vpc_options")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		return nil // inside a VPC
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-507",
		Title:       (searchOutsideVPC{}).Title(),
		Description: (searchOutsideVPC{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "vpc_options",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent (public endpoint)",
			Expected:  "vpc_options { ... } with subnet_ids and security_group_ids",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-508: Redshift cluster outside VPC
// ---------------------------------------------------------------------------

type redshiftOutsideVPC struct{}

func (redshiftOutsideVPC) ID() string { return "AEGIS-AWS-508" }
func (redshiftOutsideVPC) Title() string {
	return "Redshift cluster outside VPC"
}
func (redshiftOutsideVPC) Description() string {
	return "A Redshift cluster without cluster_subnet_group_name is not " +
		"placed in a VPC subnet group, leaving the data warehouse outside " +
		"VPC network controls."
}
func (redshiftOutsideVPC) Severity() ir.Severity { return ir.SeverityHigh }

func (redshiftOutsideVPC) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}

func (redshiftOutsideVPC) Check(r ir.Resource) []ir.Finding {
	name, span, present, known := getString(r, "cluster_subnet_group_name")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(name) != "" {
		return nil // in a VPC subnet group
	}
	actual := "absent"
	if present {
		actual = "empty string"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-508",
		Title:       (redshiftOutsideVPC{}).Title(),
		Description: (redshiftOutsideVPC{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "cluster_subnet_group_name",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "cluster_subnet_group_name set to a VPC subnet group",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-509: Transfer Server publicly accessible
// ---------------------------------------------------------------------------

type transferPublic struct{}

func (transferPublic) ID() string { return "AEGIS-AWS-509" }
func (transferPublic) Title() string {
	return "Transfer Server publicly accessible"
}
func (transferPublic) Description() string {
	return "An AWS Transfer Family server with endpoint_type PUBLIC " +
		"accepts SFTP/FTPS connections from the internet instead of being " +
		"restricted to a VPC endpoint."
}
func (transferPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (transferPublic) AppliesTo(resType string) bool {
	return resType == "aws_transfer_server"
}

func (transferPublic) Check(r ir.Resource) []ir.Finding {
	ep, span, present, known := getString(r, "endpoint_type")
	if !present {
		// Optional; the AWS API default is PUBLIC: accepts connections
		// from the internet.
		return absentInsecureDefault(transferPublic{}, r,
			"endpoint_type", "absent (provider default: PUBLIC)",
			"endpoint_type = \"VPC\"")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if ep != "PUBLIC" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-509",
		Title:       (transferPublic{}).Title(),
		Description: (transferPublic{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "endpoint_type",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "PUBLIC",
			Expected:  "endpoint_type = \"VPC\"",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-510: Load balancer listener without HTTP-to-HTTPS redirect
// ---------------------------------------------------------------------------

type lbListenerNoRedirect struct{}

func (lbListenerNoRedirect) ID() string { return "AEGIS-AWS-510" }
func (lbListenerNoRedirect) Title() string {
	return "Load balancer listener without HTTP-to-HTTPS redirect"
}
func (lbListenerNoRedirect) Description() string {
	return "A port-80 listener whose default_action does not redirect to " +
		"HTTPS serves traffic in plaintext instead of upgrading clients " +
		"to an encrypted connection."
}
func (lbListenerNoRedirect) Severity() ir.Severity { return ir.SeverityMedium }

func (lbListenerNoRedirect) AppliesTo(resType string) bool {
	return resType == "aws_lb_listener"
}

func (lbListenerNoRedirect) Check(r ir.Resource) []ir.Finding {
	pv, ok := r.Attr("port")
	if !ok || !pv.Known {
		return nil // absent or unresolved: cannot decide
	}
	var port float64
	switch n := pv.Raw.(type) {
	case float64:
		port = n
	case int:
		port = float64(n)
	case int64:
		port = float64(n)
	default:
		return nil // unexpected shape: cannot decide
	}
	if port != 80 {
		return nil
	}
	actions, span, present, known := getBlocks(r, "default_action")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	for _, a := range actions {
		if t, ok := a["type"]; ok && t.Known {
			if s, ok := t.AsString(); ok && s == "redirect" {
				return nil // redirects to HTTPS
			}
		}
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-510",
		Title:       (lbListenerNoRedirect{}).Title(),
		Description: (lbListenerNoRedirect{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "default_action",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "port 80 without redirect action",
			Expected:  "default_action { type = \"redirect\" ... } to HTTPS",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-511: SageMaker notebook not in custom VPC
// ---------------------------------------------------------------------------

type sagemakerNoVPC struct{}

func (sagemakerNoVPC) ID() string { return "AEGIS-AWS-511" }
func (sagemakerNoVPC) Title() string {
	return "SageMaker notebook not in custom VPC"
}
func (sagemakerNoVPC) Description() string {
	return "A SageMaker notebook instance without subnet_id runs outside " +
		"a customer VPC, so its traffic and data access are not governed " +
		"by VPC network controls."
}
func (sagemakerNoVPC) Severity() ir.Severity { return ir.SeverityMedium }

func (sagemakerNoVPC) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_notebook_instance"
}

func (sagemakerNoVPC) Check(r ir.Resource) []ir.Finding {
	sub, span, present, known := getString(r, "subnet_id")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(sub) != "" {
		return nil // in a VPC subnet
	}
	actual := "absent"
	if present {
		actual = "empty string"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-511",
		Title:       (sagemakerNoVPC{}).Title(),
		Description: (sagemakerNoVPC{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "subnet_id",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "subnet_id set to a VPC subnet",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-512: CloudFront distribution without geo restriction
// ---------------------------------------------------------------------------

type cloudfrontNoGeoRestrict struct{}

func (cloudfrontNoGeoRestrict) ID() string { return "AEGIS-AWS-512" }
func (cloudfrontNoGeoRestrict) Title() string {
	return "CloudFront distribution without geo restriction"
}
func (cloudfrontNoGeoRestrict) Description() string {
	return "A distribution with geo_restriction restriction_type \"none\" " +
		"serves content to every country, with no geographic access " +
		"control to limit exposure or meet data-residency requirements."
}
func (cloudfrontNoGeoRestrict) Severity() ir.Severity { return ir.SeverityMedium }

func (cloudfrontNoGeoRestrict) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

func (cloudfrontNoGeoRestrict) Check(r ir.Resource) []ir.Finding {
	restrictions, _, present, known := getBlocks(r, "restrictions")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, rb := range restrictions {
		for _, g := range blockList(rb, "geo_restriction") {
			t, ok := g["restriction_type"]
			if !ok || !t.Known {
				continue // cannot decide on this block
			}
			s, ok := t.AsString()
			if !ok || s != "none" {
				continue
			}
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-512",
				Title:       (cloudfrontNoGeoRestrict{}).Title(),
				Description: (cloudfrontNoGeoRestrict{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "restrictions.geo_restriction.restriction_type",
					Span:      evidenceSpan(t.Span, r.Span),
					Actual:    "none",
					Expected:  "restriction_type = \"whitelist\" or \"blacklist\"",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-513: AppSync API without WAF
// ---------------------------------------------------------------------------

type appsyncNoWAF struct{}

func (appsyncNoWAF) ID() string { return "AEGIS-AWS-513" }
func (appsyncNoWAF) Title() string {
	return "AppSync API without WAF"
}
func (appsyncNoWAF) Description() string {
	return "An AppSync GraphQL API with no WAFv2 web ACL association is " +
		"exposed to injection, abuse, and denial-of-service traffic with " +
		"no managed filtering in front of it."
}
func (appsyncNoWAF) Severity() ir.Severity { return ir.SeverityMedium }

func (appsyncNoWAF) AppliesTo(resType string) bool {
	return resType == "aws_appsync_graphql_api"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (appsyncNoWAF) Check(ir.Resource) []ir.Finding { return nil }

func (appsyncNoWAF) CheckAll(resources []ir.Resource) []ir.Finding {
	protected := wafProtectedAddrs(resources)
	// An association whose resource_arn is unresolvable might protect any API.
	uncertain := companionLinkUncertain(resources, "aws_wafv2_web_acl_association", "resource_arn")
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "aws_appsync_graphql_api" {
			continue
		}
		if protected[r.Address()] || uncertain {
			continue // WAF associated (or association target undecidable)
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-513",
			Title:       (appsyncNoWAF{}).Title(),
			Description: (appsyncNoWAF{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "web_acl_arn",
				Span:      evidenceSpan(ir.Span{}, r.Span),
				Actual:    "no aws_wafv2_web_acl_association for this API",
				Expected:  "an aws_wafv2_web_acl_association with resource_arn referencing this API",
			},
		})
	}
	return out
}

var _ ir.CrossResourceRule = appsyncNoWAF{}
