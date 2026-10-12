package aws

// Networking/WAF deep rules (AEGIS-AWS-740..759).
//
// Unknown-value contract: a present-but-unresolved attribute yields NO
// finding. Absent attributes are judged against the provider default,
// documented per rule. Rules never panic on unexpected shapes.

import (
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// NetworkDeepRules returns the networking/WAF deep rules, AEGIS-AWS-740..759,
// in ID order.
func NetworkDeepRules() []ir.Rule {
	return []ir.Rule{
		wafNoSampledRequests{},         // AEGIS-AWS-740
		lbListenerTlsOnPort80{},        // AEGIS-AWS-741
		vpcNoDnsHostnames{},            // AEGIS-AWS-742
		vpcNoDnsSupport{},              // AEGIS-AWS-743
		routePublicIgw{},               // AEGIS-AWS-744
		defaultSGOpenRule{},            // AEGIS-AWS-745
		defaultNaclAllowAll{},          // AEGIS-AWS-746
		vpcEndpointAutoAccept{},        // AEGIS-AWS-747
		customerGatewayPrivateAsn{},    // AEGIS-AWS-748
		route53WeightedNoHealthCheck{}, // AEGIS-AWS-749
		acmEmailValidation{},           // AEGIS-AWS-750
		apiGwRestApiPublicPolicy{},     // AEGIS-AWS-751
		cfNoLogging{},                  // AEGIS-AWS-752
		cfS3NoOAC{},                    // AEGIS-AWS-753
		cfWeakViewerCertTls{},          // AEGIS-AWS-754
		apiGwStageNoXray{},             // AEGIS-AWS-755
		apiGwStageNoClientCert{},       // AEGIS-AWS-756
		apiGwMethodNoThrottling{},      // AEGIS-AWS-757
		apiGwDeploymentNoDesc{},        // AEGIS-AWS-758
		nfwPolicyChangeProtection{},    // AEGIS-AWS-759
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-740: WAF web ACL without sampled requests
// ---------------------------------------------------------------------------

type wafNoSampledRequests struct{}

func (wafNoSampledRequests) ID() string { return "AEGIS-AWS-740" }
func (wafNoSampledRequests) Title() string {
	return "WAF web ACL with sampled requests disabled"
}
func (wafNoSampledRequests) Description() string {
	return "An aws_wafv2_web_acl whose visibility_config sets " +
		"sampled_requests_enabled = false stops AWS from storing sampled " +
		"requests, removing the primary way to see what the WAF is blocking " +
		"and tune rules. Keep sampled requests enabled."
}
func (wafNoSampledRequests) Severity() ir.Severity { return ir.SeverityLow }
func (wafNoSampledRequests) AppliesTo(resType string) bool {
	return resType == "aws_wafv2_web_acl"
}
func (wafNoSampledRequests) Check(r ir.Resource) []ir.Finding {
	s := wafNoSampledRequests{}
	cfgs, _, present, known := getBlocks(r, "visibility_config")
	if !present || !known {
		return nil // default true or unresolved: cannot flag
	}
	for _, c := range cfgs {
		val, span, vpresent, vknown := blockBool(c, "sampled_requests_enabled")
		if vpresent && !vknown {
			return nil // unresolved: cannot decide
		}
		if vpresent && !val {
			return []ir.Finding{{
				RuleID:      s.ID(),
				Title:       s.Title(),
				Description: s.Description(),
				Severity:    s.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "visibility_config.sampled_requests_enabled",
					Span:      evidenceSpan(span, r.Span),
					Actual:    "false",
					Expected:  "true",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-741: Load balancer listener with TLS protocol on port 80
// ---------------------------------------------------------------------------

type lbListenerTlsOnPort80 struct{}

func (lbListenerTlsOnPort80) ID() string { return "AEGIS-AWS-741" }
func (lbListenerTlsOnPort80) Title() string {
	return "Load balancer listener with TLS protocol on port 80"
}
func (lbListenerTlsOnPort80) Description() string {
	return "An aws_lb_listener with protocol HTTPS/TLS on port 80 is almost " +
		"certainly a misconfiguration: clients speaking plain HTTP to port " +
		"80 will fail the TLS handshake, and the intended plaintext " +
		"listener (usually redirecting to 443) is missing. Use port 443 " +
		"for TLS listeners."
}
func (lbListenerTlsOnPort80) Severity() ir.Severity { return ir.SeverityLow }
func (lbListenerTlsOnPort80) AppliesTo(resType string) bool {
	return resType == "aws_lb_listener" || resType == "aws_alb_listener"
}
func (lbListenerTlsOnPort80) Check(r ir.Resource) []ir.Finding {
	s := lbListenerTlsOnPort80{}
	port, _, ppresent, pknown := numAttr(r, "port")
	if !ppresent || !pknown || port != 80 {
		return nil // not port 80 or unresolved: cannot flag
	}
	proto, span, present, known := getString(r, "protocol")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	p := strings.ToUpper(strings.TrimSpace(proto))
	if p != "HTTPS" && p != "TLS" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "protocol",
			Span:      evidenceSpan(span, r.Span),
			Actual:    proto + " on port 80",
			Expected:  "TLS listeners on port 443; port 80 for HTTP (redirecting to HTTPS)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-742: VPC without DNS hostnames
// ---------------------------------------------------------------------------

type vpcNoDnsHostnames struct{}

func (vpcNoDnsHostnames) ID() string { return "AEGIS-AWS-742" }
func (vpcNoDnsHostnames) Title() string {
	return "VPC without DNS hostnames"
}
func (vpcNoDnsHostnames) Description() string {
	return "An aws_vpc with enable_dns_hostnames = false (the provider " +
		"default) gives instances no public DNS hostnames, which breaks " +
		"hostname-based service discovery and forces reliance on raw IPs. " +
		"Enable DNS hostnames alongside DNS support."
}
func (vpcNoDnsHostnames) Severity() ir.Severity { return ir.SeverityLow }
func (vpcNoDnsHostnames) AppliesTo(resType string) bool {
	return resType == "aws_vpc"
}
func (vpcNoDnsHostnames) Check(r ir.Resource) []ir.Finding {
	s := vpcNoDnsHostnames{}
	val, span, present, known := getBool(r, "enable_dns_hostnames")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "enable_dns_hostnames",
			"absent (provider default: false)",
			"enable_dns_hostnames = true")
	}
	if val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enable_dns_hostnames",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-743: VPC without DNS support
// ---------------------------------------------------------------------------

type vpcNoDnsSupport struct{}

func (vpcNoDnsSupport) ID() string { return "AEGIS-AWS-743" }
func (vpcNoDnsSupport) Title() string {
	return "VPC without DNS support"
}
func (vpcNoDnsSupport) Description() string {
	return "An aws_vpc with enable_dns_support = false (the provider " +
		"default) disables the Amazon DNS server, so instances cannot " +
		"resolve AWS service endpoints or private hosted zones without " +
		"custom DNS. Enable DNS support."
}
func (vpcNoDnsSupport) Severity() ir.Severity { return ir.SeverityMedium }
func (vpcNoDnsSupport) AppliesTo(resType string) bool {
	return resType == "aws_vpc"
}
func (vpcNoDnsSupport) Check(r ir.Resource) []ir.Finding {
	s := vpcNoDnsSupport{}
	val, span, present, known := getBool(r, "enable_dns_support")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "enable_dns_support",
			"absent (provider default: false)",
			"enable_dns_support = true")
	}
	if val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enable_dns_support",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-744: Route sending all traffic to an internet gateway
// ---------------------------------------------------------------------------

type routePublicIgw struct{}

func (routePublicIgw) ID() string { return "AEGIS-AWS-744" }
func (routePublicIgw) Title() string {
	return "Route sending all traffic to an internet gateway"
}
func (routePublicIgw) Description() string {
	return "An aws_route with destination_cidr_block = \"0.0.0.0/0\" via an " +
		"internet gateway makes every subnet using the route table publicly " +
		"routable. Confirm the route table is only associated with subnets " +
		"meant to be public; private subnets should route through a NAT " +
		"gateway."
}
func (routePublicIgw) Severity() ir.Severity { return ir.SeverityMedium }
func (routePublicIgw) AppliesTo(resType string) bool {
	return resType == "aws_route"
}
func (routePublicIgw) Check(r ir.Resource) []ir.Finding {
	s := routePublicIgw{}
	dst, _, dpresent, dknown := getString(r, "destination_cidr_block")
	if !dpresent || !dknown || strings.TrimSpace(dst) != "0.0.0.0/0" {
		return nil // not a default route or unresolved: cannot flag
	}
	gw, span, gpresent, gknown := getString(r, "gateway_id")
	if !gpresent || !gknown {
		return nil // unresolved: cannot decide
	}
	if !strings.HasPrefix(strings.TrimSpace(gw), "igw-") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "gateway_id",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "0.0.0.0/0 via " + strings.TrimSpace(gw),
			Expected:  "default route via a NAT gateway for private subnets",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-745: Default security group with world-open rule
// ---------------------------------------------------------------------------

type defaultSGOpenRule struct{}

func (defaultSGOpenRule) ID() string { return "AEGIS-AWS-745" }
func (defaultSGOpenRule) Title() string {
	return "Default security group with a world-open rule"
}
func (defaultSGOpenRule) Description() string {
	return "An aws_default_security_group with an ingress or egress rule " +
		"allowing 0.0.0.0/0 (or ::/0) exposes every instance launched without " +
		"an explicit group to the whole internet. The default security group " +
		"should carry no world-open rules."
}
func (defaultSGOpenRule) Severity() ir.Severity { return ir.SeverityHigh }
func (defaultSGOpenRule) AppliesTo(resType string) bool {
	return resType == "aws_default_security_group"
}

// sgBlockWorldOpen reports whether an ingress/egress block provably allows
// the world. Unresolvable CIDR lists are undecidable, never open.
func sgBlockWorldOpen(b map[string]ir.Value) bool {
	for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		cidrs, allKnown := blockStrings(b, key)
		if !allKnown {
			continue // unresolved: cannot prove
		}
		for _, c := range cidrs {
			t := strings.TrimSpace(c)
			if t == "0.0.0.0/0" || t == "::/0" {
				return true
			}
		}
	}
	return false
}

func (defaultSGOpenRule) Check(r ir.Resource) []ir.Finding {
	s := defaultSGOpenRule{}
	for _, dir := range []string{"ingress", "egress"} {
		blks, _, present, known := getBlocks(r, dir)
		if !present || !known {
			continue // absent or unresolved: nothing provable here
		}
		for _, b := range blks {
			if sgBlockWorldOpen(b) {
				return []ir.Finding{{
					RuleID:      s.ID(),
					Title:       s.Title(),
					Description: s.Description(),
					Severity:    s.Severity(),
					Resource:    r.Address(),
					Evidence: ir.Evidence{
						Attribute: dir,
						Span:      r.Span,
						Actual:    dir + " rule allows 0.0.0.0/0 or ::/0",
						Expected:  "no world-open rules on the default security group",
					},
				}}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-746: Default network ACL allowing all traffic
// ---------------------------------------------------------------------------

type defaultNaclAllowAll struct{}

func (defaultNaclAllowAll) ID() string { return "AEGIS-AWS-746" }
func (defaultNaclAllowAll) Title() string {
	return "Default network ACL with an allow-all rule"
}
func (defaultNaclAllowAll) Description() string {
	return "An aws_default_network_acl with an ingress or egress rule that " +
		"allows all protocols from 0.0.0.0/0 removes the stateless " +
		"subnet-level backstop the default NACL is meant to provide. Keep " +
		"the default NACL restrictive and put intentional rules on " +
		"purpose-built NACLs."
}
func (defaultNaclAllowAll) Severity() ir.Severity { return ir.SeverityMedium }
func (defaultNaclAllowAll) AppliesTo(resType string) bool {
	return resType == "aws_default_network_acl"
}

// naclBlockAllowAll reports whether a NACL rule block provably allows all
// traffic from anywhere. Any unresolved field is undecidable, never a hit.
func naclBlockAllowAll(b map[string]ir.Value) bool {
	action, _, apresent, aknown := blockString(b, "action")
	if !apresent || !aknown || !strings.EqualFold(strings.TrimSpace(action), "allow") {
		return false
	}
	cidr, _, cpresent, cknown := blockString(b, "cidr_block")
	if !cpresent || !cknown || strings.TrimSpace(cidr) != "0.0.0.0/0" {
		return false
	}
	proto, _, ppresent, pknown := blockString(b, "protocol")
	if !ppresent || !pknown || strings.TrimSpace(proto) != "-1" {
		return false
	}
	return true
}

func (defaultNaclAllowAll) Check(r ir.Resource) []ir.Finding {
	s := defaultNaclAllowAll{}
	for _, dir := range []string{"ingress", "egress"} {
		blks, _, present, known := getBlocks(r, dir)
		if !present || !known {
			continue
		}
		for _, b := range blks {
			if naclBlockAllowAll(b) {
				return []ir.Finding{{
					RuleID:      s.ID(),
					Title:       s.Title(),
					Description: s.Description(),
					Severity:    s.Severity(),
					Resource:    r.Address(),
					Evidence: ir.Evidence{
						Attribute: dir,
						Span:      r.Span,
						Actual:    dir + " rule allows all protocols from 0.0.0.0/0",
						Expected:  "no allow-all rules on the default network ACL",
					},
				}}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-747: VPC endpoint with auto-accept enabled
// ---------------------------------------------------------------------------

type vpcEndpointAutoAccept struct{}

func (vpcEndpointAutoAccept) ID() string { return "AEGIS-AWS-747" }
func (vpcEndpointAutoAccept) Title() string {
	return "VPC endpoint with auto-accept enabled"
}
func (vpcEndpointAutoAccept) Description() string {
	return "An aws_vpc_endpoint with auto_accept = true automatically " +
		"accepts interface endpoint connection requests without review, " +
		"letting unintended consumers attach. Require manual acceptance " +
		"unless the endpoint is intentionally open."
}
func (vpcEndpointAutoAccept) Severity() ir.Severity { return ir.SeverityMedium }
func (vpcEndpointAutoAccept) AppliesTo(resType string) bool {
	return resType == "aws_vpc_endpoint"
}
func (vpcEndpointAutoAccept) Check(r ir.Resource) []ir.Finding {
	s := vpcEndpointAutoAccept{}
	val, span, present, known := getBool(r, "auto_accept")
	if !present || !known {
		return nil // default false or unresolved: cannot flag
	}
	if !val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "auto_accept",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (manual acceptance)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-748: Customer gateway with well-known private ASN
// ---------------------------------------------------------------------------

type customerGatewayPrivateAsn struct{}

func (customerGatewayPrivateAsn) ID() string { return "AEGIS-AWS-748" }
func (customerGatewayPrivateAsn) Title() string {
	return "Customer gateway using the well-known private ASN 65000"
}
func (customerGatewayPrivateAsn) Description() string {
	return "An aws_customer_gateway with bgp_asn = 65000 uses the " +
		"commonly-chosen example ASN from AWS documentation. Colliding ASNs " +
		"across peers cause BGP session confusion and misrouted VPN " +
		"traffic. Use a private ASN unique to the organization " +
		"(64512-65534)."
}
func (customerGatewayPrivateAsn) Severity() ir.Severity { return ir.SeverityLow }
func (customerGatewayPrivateAsn) AppliesTo(resType string) bool {
	return resType == "aws_customer_gateway"
}
func (customerGatewayPrivateAsn) Check(r ir.Resource) []ir.Finding {
	s := customerGatewayPrivateAsn{}
	n, span, present, known := numAttr(r, "bgp_asn")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if n != 65000 {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "bgp_asn",
			Span:      evidenceSpan(span, r.Span),
			Actual:    strconv.FormatFloat(n, 'f', -1, 64),
			Expected:  "a private ASN unique to the organization (64512-65534)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-749: Route53 weighted record without health check
// ---------------------------------------------------------------------------

type route53WeightedNoHealthCheck struct{}

func (route53WeightedNoHealthCheck) ID() string { return "AEGIS-AWS-749" }
func (route53WeightedNoHealthCheck) Title() string {
	return "Route53 weighted record without a health check"
}
func (route53WeightedNoHealthCheck) Description() string {
	return "An aws_route53_record using weighted_routing_policy without " +
		"health_check_id keeps sending its share of traffic to an endpoint " +
		"even when that endpoint is down, turning a partial outage into " +
		"user-visible errors. Attach a health check so Route53 stops " +
		"routing to failed endpoints."
}
func (route53WeightedNoHealthCheck) Severity() ir.Severity { return ir.SeverityLow }
func (route53WeightedNoHealthCheck) AppliesTo(resType string) bool {
	return resType == "aws_route53_record"
}
func (route53WeightedNoHealthCheck) Check(r ir.Resource) []ir.Finding {
	s := route53WeightedNoHealthCheck{}
	_, _, present, known := getBlocks(r, "weighted_routing_policy")
	if !present || !known {
		return nil // not weighted routing or unresolved: cannot flag
	}
	hc, _, hcpresent, hcknown := getString(r, "health_check_id")
	if hcpresent && !hcknown {
		return nil // unresolved: cannot decide
	}
	if hcpresent && strings.TrimSpace(hc) != "" {
		return nil
	}
	return absentInsecureDefault(s, r, "health_check_id",
		"absent (traffic keeps flowing to failed endpoints)",
		"health_check_id referencing a Route53 health check")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-750: ACM certificate validated by email
// ---------------------------------------------------------------------------

type acmEmailValidation struct{}

func (acmEmailValidation) ID() string { return "AEGIS-AWS-750" }
func (acmEmailValidation) Title() string {
	return "ACM certificate using email validation"
}
func (acmEmailValidation) Description() string {
	return "An aws_acm_certificate with validation_method = \"EMAIL\" " +
		"depends on someone clicking an approval link sent to domain " +
		"contact addresses, which is phishable and often lands in an " +
		"unmonitored mailbox. Use DNS validation, which is automatic and " +
		"auditable."
}
func (acmEmailValidation) Severity() ir.Severity { return ir.SeverityMedium }
func (acmEmailValidation) AppliesTo(resType string) bool {
	return resType == "aws_acm_certificate"
}
func (acmEmailValidation) Check(r ir.Resource) []ir.Finding {
	s := acmEmailValidation{}
	method, span, present, known := getString(r, "validation_method")
	if !present || !known {
		return nil // default DNS or unresolved: cannot flag
	}
	if !strings.EqualFold(strings.TrimSpace(method), "EMAIL") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "validation_method",
			Span:      evidenceSpan(span, r.Span),
			Actual:    method,
			Expected:  "\"DNS\"",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-751: API Gateway REST API with public resource policy
// ---------------------------------------------------------------------------

type apiGwRestApiPublicPolicy struct{}

func (apiGwRestApiPublicPolicy) ID() string { return "AEGIS-AWS-751" }
func (apiGwRestApiPublicPolicy) Title() string {
	return "API Gateway REST API with a public resource policy"
}
func (apiGwRestApiPublicPolicy) Description() string {
	return "An aws_api_gateway_rest_api whose policy allows " +
		"\"Principal\": \"*\" exposes the API's execute-api endpoint to any " +
		"AWS principal, bypassing method-level authorization. Restrict the " +
		"resource policy to the intended accounts, VPCs, or source IPs."
}
func (apiGwRestApiPublicPolicy) Severity() ir.Severity { return ir.SeverityHigh }
func (apiGwRestApiPublicPolicy) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_rest_api"
}
func (apiGwRestApiPublicPolicy) Check(r ir.Resource) []ir.Finding {
	s := apiGwRestApiPublicPolicy{}
	pol, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // no policy or unresolved: cannot decide
	}
	flat := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(pol, " ", ""), "\n", ""), "\t", "")
	if !strings.Contains(flat, "\"Effect\":\"Allow\"") {
		return nil
	}
	if !strings.Contains(flat, "\"Principal\":\"*\"") &&
		!strings.Contains(flat, "\"Principal\":{\"AWS\":\"*\"}") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "resource policy allows \"Principal\": \"*\"",
			Expected:  "resource policy restricted to intended principals",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-752: CloudFront distribution without access logging
// ---------------------------------------------------------------------------

type cfNoLogging struct{}

func (cfNoLogging) ID() string { return "AEGIS-AWS-752" }
func (cfNoLogging) Title() string {
	return "CloudFront distribution without access logging"
}
func (cfNoLogging) Description() string {
	return "An aws_cloudfront_distribution without a logging_config block " +
		"emits no access logs, leaving no record of who requested what " +
		"through the CDN during incident response. Enable standard logging " +
		"to an S3 bucket."
}
func (cfNoLogging) Severity() ir.Severity { return ir.SeverityMedium }
func (cfNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}
func (cfNoLogging) Check(r ir.Resource) []ir.Finding {
	s := cfNoLogging{}
	_, _, present, known := getBlocks(r, "logging_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "logging_config",
			"absent (no access logs emitted)",
			"logging_config { bucket = <log bucket> }")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-753: CloudFront S3 origin without origin access control
// ---------------------------------------------------------------------------

type cfS3NoOAC struct{}

func (cfS3NoOAC) ID() string { return "AEGIS-AWS-753" }
func (cfS3NoOAC) Title() string {
	return "CloudFront S3 origin without origin access control"
}
func (cfS3NoOAC) Description() string {
	return "An aws_cloudfront_distribution whose S3 origin sets neither " +
		"origin_access_control_id nor a legacy origin_access_identity " +
		"reaches the bucket as an anonymous client, which forces the bucket " +
		"toward public access. Attach an origin access control (OAC) and " +
		"keep the bucket private."
}
func (cfS3NoOAC) Severity() ir.Severity { return ir.SeverityHigh }
func (cfS3NoOAC) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}
func (cfS3NoOAC) Check(r ir.Resource) []ir.Finding {
	s := cfS3NoOAC{}
	origins, _, present, known := getBlocks(r, "origin")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	for _, o := range origins {
		s3cfgs := blockList(o, "s3_origin_config")
		if len(s3cfgs) == 0 {
			continue // not an S3 origin
		}
		oac, _, oacPresent, oacKnown := blockString(o, "origin_access_control_id")
		if oacPresent && !oacKnown {
			return nil // unresolved: cannot decide
		}
		if oacPresent && strings.TrimSpace(oac) != "" {
			continue // OAC attached
		}
		legacyOAI := false
		for _, soc := range s3cfgs {
			oai, _, opresent, oknown := blockString(soc, "origin_access_identity")
			if opresent && !oknown {
				return nil // unresolved: cannot decide
			}
			if opresent && strings.TrimSpace(oai) != "" {
				legacyOAI = true // legacy OAI is rule 825's territory
			}
		}
		if legacyOAI {
			continue
		}
		return []ir.Finding{{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "origin.origin_access_control_id",
				Span:      r.Span,
				Actual:    "absent on an S3 origin (no OAC, no legacy OAI)",
				Expected:  "origin_access_control_id referencing an OAC",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-754: CloudFront viewer certificate with TLS 1.0 minimum
// ---------------------------------------------------------------------------

type cfWeakViewerCertTls struct{}

func (cfWeakViewerCertTls) ID() string { return "AEGIS-AWS-754" }
func (cfWeakViewerCertTls) Title() string {
	return "CloudFront viewer certificate with TLS 1.0 minimum"
}
func (cfWeakViewerCertTls) Description() string {
	return "An aws_cloudfront_distribution whose viewer_certificate sets " +
		"minimum_protocol_version = \"TLSv1\" negotiates TLS 1.0 with " +
		"viewers, exposing them to protocol downgrade attacks. Use " +
		"TLSv1.2_2021 or later."
}
func (cfWeakViewerCertTls) Severity() ir.Severity { return ir.SeverityHigh }
func (cfWeakViewerCertTls) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}
func (cfWeakViewerCertTls) Check(r ir.Resource) []ir.Finding {
	s := cfWeakViewerCertTls{}
	certs, _, present, known := getBlocks(r, "viewer_certificate")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	for _, c := range certs {
		ver, span, vpresent, vknown := blockString(c, "minimum_protocol_version")
		if vpresent && !vknown {
			return nil // unresolved: cannot decide
		}
		if vpresent && strings.EqualFold(strings.TrimSpace(ver), "TLSv1") {
			return []ir.Finding{{
				RuleID:      s.ID(),
				Title:       s.Title(),
				Description: s.Description(),
				Severity:    s.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "viewer_certificate.minimum_protocol_version",
					Span:      evidenceSpan(span, r.Span),
					Actual:    ver,
					Expected:  "\"TLSv1.2_2021\" or later",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-755: API Gateway stage without X-Ray tracing
// ---------------------------------------------------------------------------

type apiGwStageNoXray struct{}

func (apiGwStageNoXray) ID() string { return "AEGIS-AWS-755" }
func (apiGwStageNoXray) Title() string {
	return "API Gateway stage without X-Ray tracing"
}
func (apiGwStageNoXray) Description() string {
	return "An aws_api_gateway_stage with xray_tracing_enabled unset or " +
		"false (the provider default) emits no X-Ray traces, losing " +
		"distributed visibility into API requests. Enable X-Ray tracing on " +
		"the stage."
}
func (apiGwStageNoXray) Severity() ir.Severity { return ir.SeverityLow }
func (apiGwStageNoXray) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_stage"
}
func (apiGwStageNoXray) Check(r ir.Resource) []ir.Finding {
	s := apiGwStageNoXray{}
	val, span, present, known := getBool(r, "xray_tracing_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "xray_tracing_enabled",
			"absent (provider default: false)",
			"xray_tracing_enabled = true")
	}
	if val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "xray_tracing_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-756: API Gateway stage without client certificate
// ---------------------------------------------------------------------------

type apiGwStageNoClientCert struct{}

func (apiGwStageNoClientCert) ID() string { return "AEGIS-AWS-756" }
func (apiGwStageNoClientCert) Title() string {
	return "API Gateway stage without a client certificate"
}
func (apiGwStageNoClientCert) Description() string {
	return "An aws_api_gateway_stage without client_certificate_id cannot " +
		"present a client certificate to backend integrations, so backends " +
		"cannot authenticate that calls genuinely come from API Gateway. " +
		"Generate a client certificate and attach it to the stage when the " +
		"backend supports mutual authentication."
}
func (apiGwStageNoClientCert) Severity() ir.Severity { return ir.SeverityLow }
func (apiGwStageNoClientCert) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_stage"
}
func (apiGwStageNoClientCert) Check(r ir.Resource) []ir.Finding {
	s := apiGwStageNoClientCert{}
	v, ok := r.Attributes["client_certificate_id"]
	if !ok {
		return absentInsecureDefault(s, r, "client_certificate_id",
			"absent (no client certificate for backend auth)",
			"client_certificate_id referencing an API Gateway client certificate")
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-757: API Gateway method settings without throttling
// ---------------------------------------------------------------------------

type apiGwMethodNoThrottling struct{}

func (apiGwMethodNoThrottling) ID() string { return "AEGIS-AWS-757" }
func (apiGwMethodNoThrottling) Title() string {
	return "API Gateway method settings without throttling limits"
}
func (apiGwMethodNoThrottling) Description() string {
	return "An aws_api_gateway_method_settings settings block without " +
		"throttling_burst_limit leaves the method unthrottled, so traffic " +
		"spikes or abusive clients can overwhelm backends and inflate " +
		"bills. Set throttling_burst_limit and throttling_rate_limit."
}
func (apiGwMethodNoThrottling) Severity() ir.Severity { return ir.SeverityLow }
func (apiGwMethodNoThrottling) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_method_settings"
}
func (apiGwMethodNoThrottling) Check(r ir.Resource) []ir.Finding {
	s := apiGwMethodNoThrottling{}
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil // no settings blocks or unresolved: cannot decide
	}
	for _, b := range settings {
		_, _, bpresent, bknown := blockNum(b, "throttling_burst_limit")
		if bpresent && !bknown {
			return nil // unresolved: cannot decide
		}
		if !bpresent {
			return []ir.Finding{{
				RuleID:      s.ID(),
				Title:       s.Title(),
				Description: s.Description(),
				Severity:    s.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "settings.throttling_burst_limit",
					Span:      r.Span,
					Actual:    "absent (no throttling limit)",
					Expected:  "throttling_burst_limit and throttling_rate_limit set",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-758: API Gateway deployment without description
// ---------------------------------------------------------------------------

type apiGwDeploymentNoDesc struct{}

func (apiGwDeploymentNoDesc) ID() string { return "AEGIS-AWS-758" }
func (apiGwDeploymentNoDesc) Title() string {
	return "API Gateway deployment without a description"
}
func (apiGwDeploymentNoDesc) Description() string {
	return "An aws_api_gateway_deployment without a description is " +
		"indistinguishable from other deployments in history, slowing " +
		"rollback decisions during incidents. Describe what each deployment " +
		"changes."
}
func (apiGwDeploymentNoDesc) Severity() ir.Severity { return ir.SeverityLow }
func (apiGwDeploymentNoDesc) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_deployment"
}
func (apiGwDeploymentNoDesc) Check(r ir.Resource) []ir.Finding {
	s := apiGwDeploymentNoDesc{}
	desc, span, present, known := getString(r, "description")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(desc) != "" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "description",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent or empty",
			Expected:  "a description of what the deployment changes",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-759: Network Firewall without policy change protection
// ---------------------------------------------------------------------------

type nfwPolicyChangeProtection struct{}

func (nfwPolicyChangeProtection) ID() string { return "AEGIS-AWS-759" }
func (nfwPolicyChangeProtection) Title() string {
	return "Network Firewall without firewall policy change protection"
}
func (nfwPolicyChangeProtection) Description() string {
	return "An aws_networkfirewall_firewall with " +
		"firewall_policy_change_protection unset or false (the provider " +
		"default) lets any principal with network-firewall permissions " +
		"swap the firewall policy, silently dropping inspection. Enable " +
		"policy change protection."
}
func (nfwPolicyChangeProtection) Severity() ir.Severity { return ir.SeverityLow }
func (nfwPolicyChangeProtection) AppliesTo(resType string) bool {
	return resType == "aws_networkfirewall_firewall"
}
func (nfwPolicyChangeProtection) Check(r ir.Resource) []ir.Finding {
	s := nfwPolicyChangeProtection{}
	val, span, present, known := getBool(r, "firewall_policy_change_protection")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "firewall_policy_change_protection",
			"absent (provider default: false)",
			"firewall_policy_change_protection = true")
	}
	if val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "firewall_policy_change_protection",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "true",
		},
	}}
}
