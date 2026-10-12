package aws

import (
	"strings"

	"aegis/internal/ir"
)

// Edge2Rules returns the final NETWORK & EDGE rule block (401-410), in ID
// order. The parent wires it into the pack; pack.go is not touched here.
func Edge2Rules() []ir.Rule {
	return []ir.Rule{
		elbHTTPListener{},           // AEGIS-AWS-401
		elbNoAccessLogs{},           // AEGIS-AWS-402
		apiGWMethodNoAuth{},         // AEGIS-AWS-403
		apiGWv2RouteNoAuth{},        // AEGIS-AWS-404
		cloudFrontHTTPOrigin{},      // AEGIS-AWS-405
		lambdaPermissionOpen{},      // AEGIS-AWS-406
		lambdaFunctionURLNoAuth{},   // AEGIS-AWS-407
		ecrPolicyPublic{},           // AEGIS-AWS-408
		codePipelineWebhookUnauth{}, // AEGIS-AWS-409
		apiGWAPIKeyHardcoded{},      // AEGIS-AWS-410
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-401: Classic ELB with HTTP listener
// ---------------------------------------------------------------------------

type elbHTTPListener struct{}

func (elbHTTPListener) ID() string { return "AEGIS-AWS-401" }
func (elbHTTPListener) Title() string {
	return "Classic ELB with plain-HTTP listener"
}
func (elbHTTPListener) Description() string {
	return "A classic load balancer listener using HTTP terminates TLS " +
		"nowhere: client traffic crosses the network in cleartext. Use " +
		"HTTPS listeners."
}
func (elbHTTPListener) Severity() ir.Severity { return ir.SeverityHigh }
func (elbHTTPListener) AppliesTo(resType string) bool {
	return resType == "aws_elb"
}

func (elbHTTPListener) Check(r ir.Resource) []ir.Finding {
	listeners, _, present, known := getBlocks(r, "listener")
	if !present || !known {
		return nil
	}
	for _, l := range listeners {
		proto, span, ppresent, pknown := blockString(l, "lb_protocol")
		if !ppresent || !pknown {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(proto), "HTTP") {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-401",
				Title:       (elbHTTPListener{}).Title(),
				Description: (elbHTTPListener{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "lb_protocol",
					Span:      evidenceSpan(span, r.Span),
					Actual:    proto,
					Expected:  "HTTPS",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-402: Classic ELB without access logs
// ---------------------------------------------------------------------------

type elbNoAccessLogs struct{}

func (elbNoAccessLogs) ID() string { return "AEGIS-AWS-402" }
func (elbNoAccessLogs) Title() string {
	return "Classic ELB without access logging"
}
func (elbNoAccessLogs) Description() string {
	return "Without access logs there is no request-level audit trail for " +
		"the load balancer. Enable access_logs."
}
func (elbNoAccessLogs) Severity() ir.Severity { return ir.SeverityMedium }
func (elbNoAccessLogs) AppliesTo(resType string) bool {
	return resType == "aws_elb"
}

func (elbNoAccessLogs) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "access_logs")
	if !present {
		return noAccessLogsFinding402(r, ir.Span{}, "absent (provider default: disabled)")
	}
	if !known || len(blks) == 0 {
		return nil // unresolved: cannot decide
	}
	enabled, span, epresent, eknown := blockBool(blks[0], "enabled")
	if !epresent || !eknown || enabled {
		return nil
	}
	return noAccessLogsFinding402(r, span, "false")
}

func noAccessLogsFinding402(r ir.Resource, span ir.Span, actual string) []ir.Finding {
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-402",
		Title:       (elbNoAccessLogs{}).Title(),
		Description: (elbNoAccessLogs{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "access_logs.enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "access_logs { enabled = true }",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-403: API Gateway method without authorization
// ---------------------------------------------------------------------------

type apiGWMethodNoAuth struct{}

func (apiGWMethodNoAuth) ID() string { return "AEGIS-AWS-403" }
func (apiGWMethodNoAuth) Title() string {
	return "API Gateway method without authorization"
}
func (apiGWMethodNoAuth) Description() string {
	return "A REST API method with authorization NONE is invocable by " +
		"anyone with the endpoint URL. Attach an authorizer, IAM auth, " +
		"or a resource policy."
}
func (apiGWMethodNoAuth) Severity() ir.Severity { return ir.SeverityHigh }
func (apiGWMethodNoAuth) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_method"
}

func (apiGWMethodNoAuth) Check(r ir.Resource) []ir.Finding {
	auth, span, present, known := getString(r, "authorization")
	if !present || !known {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth), "NONE") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-403",
		Title:       (apiGWMethodNoAuth{}).Title(),
		Description: (apiGWMethodNoAuth{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "authorization",
			Span:      evidenceSpan(span, r.Span),
			Actual:    auth,
			Expected:  "an authorizer (CUSTOM, COGNITO_USER_POOLS, AWS_IAM)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-404: API Gateway v2 route without authorization
// ---------------------------------------------------------------------------

type apiGWv2RouteNoAuth struct{}

func (apiGWv2RouteNoAuth) ID() string { return "AEGIS-AWS-404" }
func (apiGWv2RouteNoAuth) Title() string {
	return "API Gateway v2 route without authorization"
}
func (apiGWv2RouteNoAuth) Description() string {
	return "An HTTP/WebSocket API route with authorization_type NONE is " +
		"publicly invocable. Require JWT or IAM authorization."
}
func (apiGWv2RouteNoAuth) Severity() ir.Severity { return ir.SeverityHigh }
func (apiGWv2RouteNoAuth) AppliesTo(resType string) bool {
	return resType == "aws_apigatewayv2_route"
}

func (apiGWv2RouteNoAuth) Check(r ir.Resource) []ir.Finding {
	auth, span, present, known := getString(r, "authorization_type")
	if !present {
		// Optional; the AWS API default is NONE: publicly invocable.
		return absentInsecureDefault(apiGWv2RouteNoAuth{}, r,
			"authorization_type", "absent (provider default: NONE)", "JWT or AWS_IAM")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(auth), "NONE") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-404",
		Title:       (apiGWv2RouteNoAuth{}).Title(),
		Description: (apiGWv2RouteNoAuth{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "authorization_type",
			Span:      evidenceSpan(span, r.Span),
			Actual:    auth,
			Expected:  "JWT or AWS_IAM",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-405: CloudFront custom origin over HTTP
// ---------------------------------------------------------------------------

type cloudFrontHTTPOrigin struct{}

func (cloudFrontHTTPOrigin) ID() string { return "AEGIS-AWS-405" }
func (cloudFrontHTTPOrigin) Title() string {
	return "CloudFront custom origin fetched over plain HTTP"
}
func (cloudFrontHTTPOrigin) Description() string {
	return "A custom origin with origin_protocol_policy http-only means " +
		"CloudFront talks to the origin in cleartext. Use https-only or " +
		"match-viewer."
}
func (cloudFrontHTTPOrigin) Severity() ir.Severity { return ir.SeverityHigh }
func (cloudFrontHTTPOrigin) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

func (cloudFrontHTTPOrigin) Check(r ir.Resource) []ir.Finding {
	origins, _, present, known := getBlocks(r, "origin")
	if !present || !known {
		return nil
	}
	for _, o := range origins {
		for _, coc := range blockList(o, "custom_origin_config") {
			policy, span, ppresent, pknown := blockString(coc, "origin_protocol_policy")
			if !ppresent || !pknown {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(policy), "http-only") {
				return []ir.Finding{{
					RuleID:      "AEGIS-AWS-405",
					Title:       (cloudFrontHTTPOrigin{}).Title(),
					Description: (cloudFrontHTTPOrigin{}).Description(),
					Severity:    ir.SeverityHigh,
					Resource:    r.Address(),
					Evidence: ir.Evidence{
						Attribute: "origin.custom_origin_config.origin_protocol_policy",
						Span:      evidenceSpan(span, r.Span),
						Actual:    policy,
						Expected:  "https-only or match-viewer",
					},
				}}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-406: Lambda permission open to all
// ---------------------------------------------------------------------------

type lambdaPermissionOpen struct{}

func (lambdaPermissionOpen) ID() string { return "AEGIS-AWS-406" }
func (lambdaPermissionOpen) Title() string {
	return "Lambda permission grants invoke to everyone"
}
func (lambdaPermissionOpen) Description() string {
	return "A Lambda resource policy with principal \"*\" lets any AWS " +
		"principal invoke the function. Scope the principal to the " +
		"intended service or account."
}
func (lambdaPermissionOpen) Severity() ir.Severity { return ir.SeverityHigh }
func (lambdaPermissionOpen) AppliesTo(resType string) bool {
	return resType == "aws_lambda_permission"
}

func (lambdaPermissionOpen) Check(r ir.Resource) []ir.Finding {
	principal, span, present, known := getString(r, "principal")
	if !present || !known {
		return nil
	}
	if strings.TrimSpace(principal) != "*" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-406",
		Title:       (lambdaPermissionOpen{}).Title(),
		Description: (lambdaPermissionOpen{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "principal",
			Span:      evidenceSpan(span, r.Span),
			Actual:    principal,
			Expected:  "a specific service or account principal",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-407: Lambda function URL without auth
// ---------------------------------------------------------------------------

type lambdaFunctionURLNoAuth struct{}

func (lambdaFunctionURLNoAuth) ID() string { return "AEGIS-AWS-407" }
func (lambdaFunctionURLNoAuth) Title() string {
	return "Lambda function URL without authorization"
}
func (lambdaFunctionURLNoAuth) Description() string {
	return "A function URL with authorization_type NONE exposes the " +
		"function as a public HTTPS endpoint. Require AWS_IAM."
}
func (lambdaFunctionURLNoAuth) Severity() ir.Severity { return ir.SeverityHigh }
func (lambdaFunctionURLNoAuth) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function_url"
}

func (lambdaFunctionURLNoAuth) Check(r ir.Resource) []ir.Finding {
	auth, span, present, known := getString(r, "authorization_type")
	if !present {
		// Optional; the AWS API default is NONE: public HTTPS endpoint.
		return absentInsecureDefault(lambdaFunctionURLNoAuth{}, r,
			"authorization_type", "absent (provider default: NONE)", "AWS_IAM")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(auth), "NONE") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-407",
		Title:       (lambdaFunctionURLNoAuth{}).Title(),
		Description: (lambdaFunctionURLNoAuth{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "authorization_type",
			Span:      evidenceSpan(span, r.Span),
			Actual:    auth,
			Expected:  "AWS_IAM",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-408: ECR repository policy allows public principal
// ---------------------------------------------------------------------------

type ecrPolicyPublic struct{}

func (ecrPolicyPublic) ID() string { return "AEGIS-AWS-408" }
func (ecrPolicyPublic) Title() string {
	return "ECR repository policy allows public principal"
}
func (ecrPolicyPublic) Description() string {
	return "An Allow statement with Principal \"*\" on a repository " +
		"policy lets anyone pull (or push) container images."
}
func (ecrPolicyPublic) Severity() ir.Severity { return ir.SeverityHigh }
func (ecrPolicyPublic) AppliesTo(resType string) bool {
	return resType == "aws_ecr_repository_policy"
}

func (ecrPolicyPublic) Check(r ir.Resource) []ir.Finding {
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil
	}
	if !policyAllowsPublicPrincipal(doc) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-408",
		Title:       (ecrPolicyPublic{}).Title(),
		Description: (ecrPolicyPublic{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "Allow statement with Principal \"*\"",
			Expected:  "scoped principals only",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-409: CodePipeline webhook unauthenticated
// ---------------------------------------------------------------------------

type codePipelineWebhookUnauth struct{}

func (codePipelineWebhookUnauth) ID() string { return "AEGIS-AWS-409" }
func (codePipelineWebhookUnauth) Title() string {
	return "CodePipeline webhook without authentication"
}
func (codePipelineWebhookUnauth) Description() string {
	return "A webhook with authentication UNAUTHENTICATED lets anyone " +
		"trigger the pipeline. Use GITHUB_HMAC, IP, or both."
}
func (codePipelineWebhookUnauth) Severity() ir.Severity { return ir.SeverityHigh }
func (codePipelineWebhookUnauth) AppliesTo(resType string) bool {
	return resType == "aws_codepipeline_webhook"
}

func (codePipelineWebhookUnauth) Check(r ir.Resource) []ir.Finding {
	auth, span, present, known := getString(r, "authentication")
	if !present || !known {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth), "UNAUTHENTICATED") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-409",
		Title:       (codePipelineWebhookUnauth{}).Title(),
		Description: (codePipelineWebhookUnauth{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "authentication",
			Span:      evidenceSpan(span, r.Span),
			Actual:    auth,
			Expected:  "GITHUB_HMAC or IP",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-410: API Gateway API key hardcoded
// ---------------------------------------------------------------------------

type apiGWAPIKeyHardcoded struct{}

func (apiGWAPIKeyHardcoded) ID() string { return "AEGIS-AWS-410" }
func (apiGWAPIKeyHardcoded) Title() string {
	return "API Gateway API key hardcoded in config"
}
func (apiGWAPIKeyHardcoded) Description() string {
	return "An API key written as a literal in Terraform config is stored " +
		"in state and version control. Let AWS generate the key or source " +
		"it from a secrets manager. The key value is never included in " +
		"findings."
}
func (apiGWAPIKeyHardcoded) Severity() ir.Severity { return ir.SeverityHigh }
func (apiGWAPIKeyHardcoded) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_api_key"
}

func (apiGWAPIKeyHardcoded) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "value")
	if !present || !known || strings.TrimSpace(val) == "" {
		return nil // absent, unresolved, or empty: nothing hardcoded
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-410",
		Title:       (apiGWAPIKeyHardcoded{}).Title(),
		Description: (apiGWAPIKeyHardcoded{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "value",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "[REDACTED]",
			Expected:  "no hardcoded key value",
		},
	}}
}
