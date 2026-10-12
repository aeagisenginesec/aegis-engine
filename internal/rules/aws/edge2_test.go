package aws

// Rule IDs covered in this file: AEGIS-AWS-401, AEGIS-AWS-403, AEGIS-AWS-404, AEGIS-AWS-405, AEGIS-AWS-406, AEGIS-AWS-407, AEGIS-AWS-408, AEGIS-AWS-409, AEGIS-AWS-410

import (
	"fmt"
	"testing"

	"aegis/internal/ir"
)

// --- 401: Classic ELB with HTTP listener ---

func Test401_HTTPListenerFires(t *testing.T) {
	r := res("aws_elb", "web", map[string]ir.Value{
		"listener": blks(3, blk("lb_protocol", ks("HTTP", 4))),
	})
	fs := runRule(elbHTTPListener{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh || fs[0].Evidence.Actual != "HTTP" {
		t.Fatalf("wrong finding: %+v", fs[0])
	}
}

func Test401_HTTPSListenerQuiet(t *testing.T) {
	r := res("aws_elb", "web", map[string]ir.Value{
		"listener": blks(3, blk("lb_protocol", ks("HTTPS", 4))),
	})
	if fs := runRule(elbHTTPListener{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test401_UnknownProtocolQuiet(t *testing.T) {
	r := res("aws_elb", "web", map[string]ir.Value{
		"listener": blks(3, blk("lb_protocol", ku(4))),
	})
	if fs := runRule(elbHTTPListener{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 402: Classic ELB without access logs ---

func Test402_AbsentBlockFires(t *testing.T) {
	fs := runRule(elbNoAccessLogs{}, res("aws_elb", "web", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test402_DisabledFires(t *testing.T) {
	r := res("aws_elb", "web", map[string]ir.Value{
		"access_logs": blks(3, blk("enabled", kv(false, 4))),
	})
	if fs := runRule(elbNoAccessLogs{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test402_EnabledQuiet(t *testing.T) {
	r := res("aws_elb", "web", map[string]ir.Value{
		"access_logs": blks(3, blk("enabled", kv(true, 4))),
	})
	if fs := runRule(elbNoAccessLogs{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test402_UnknownQuiet(t *testing.T) {
	r := res("aws_elb", "web", map[string]ir.Value{
		"access_logs": {Raw: nil, Known: false, Span: spanAt(3)},
	})
	if fs := runRule(elbNoAccessLogs{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 403: API Gateway method without authorization ---

func Test403_NoneFires(t *testing.T) {
	r := res("aws_api_gateway_method", "get", map[string]ir.Value{
		"authorization": ks("NONE", 3),
	})
	fs := runRule(apiGWMethodNoAuth{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test403_AuthorizerQuiet(t *testing.T) {
	r := res("aws_api_gateway_method", "get", map[string]ir.Value{
		"authorization": ks("CUSTOM", 3),
	})
	if fs := runRule(apiGWMethodNoAuth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test403_UnknownQuiet(t *testing.T) {
	r := res("aws_api_gateway_method", "get", map[string]ir.Value{
		"authorization": ku(3),
	})
	if fs := runRule(apiGWMethodNoAuth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 404: API Gateway v2 route without authorization ---

func Test404_NoneFires(t *testing.T) {
	r := res("aws_apigatewayv2_route", "get", map[string]ir.Value{
		"authorization_type": ks("NONE", 3),
	})
	if fs := runRule(apiGWv2RouteNoAuth{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test404_JWTQuiet(t *testing.T) {
	r := res("aws_apigatewayv2_route", "get", map[string]ir.Value{
		"authorization_type": ks("JWT", 3),
	})
	if fs := runRule(apiGWv2RouteNoAuth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test404_UnknownQuiet(t *testing.T) {
	r := res("aws_apigatewayv2_route", "get", map[string]ir.Value{
		"authorization_type": ku(3),
	})
	if fs := runRule(apiGWv2RouteNoAuth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 405: CloudFront custom origin over HTTP ---

func httpOriginRes() ir.Resource {
	return res("aws_cloudfront_distribution", "cdn", map[string]ir.Value{
		"origin": blks(3, blk(
			"custom_origin_config", blks(4, blk(
				"origin_protocol_policy", ks("http-only", 5),
			)),
		)),
	})
}

func Test405_HTTPOnlyFires(t *testing.T) {
	if fs := runRule(cloudFrontHTTPOrigin{}, httpOriginRes()); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test405_HTTPSOnlyQuiet(t *testing.T) {
	r := res("aws_cloudfront_distribution", "cdn", map[string]ir.Value{
		"origin": blks(3, blk(
			"custom_origin_config", blks(4, blk(
				"origin_protocol_policy", ks("https-only", 5),
			)),
		)),
	})
	if fs := runRule(cloudFrontHTTPOrigin{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test405_UnknownPolicyQuiet(t *testing.T) {
	r := res("aws_cloudfront_distribution", "cdn", map[string]ir.Value{
		"origin": blks(3, blk(
			"custom_origin_config", blks(4, blk(
				"origin_protocol_policy", ku(5),
			)),
		)),
	})
	if fs := runRule(cloudFrontHTTPOrigin{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 406: Lambda permission open to all ---

func Test406_StarFires(t *testing.T) {
	r := res("aws_lambda_permission", "open", map[string]ir.Value{
		"principal": ks("*", 3),
	})
	if fs := runRule(lambdaPermissionOpen{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test406_ScopedQuiet(t *testing.T) {
	r := res("aws_lambda_permission", "ok", map[string]ir.Value{
		"principal": ks("events.amazonaws.com", 3),
	})
	if fs := runRule(lambdaPermissionOpen{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test406_UnknownQuiet(t *testing.T) {
	r := res("aws_lambda_permission", "x", map[string]ir.Value{
		"principal": ku(3),
	})
	if fs := runRule(lambdaPermissionOpen{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 407: Lambda function URL without auth ---

func Test407_NoneFires(t *testing.T) {
	r := res("aws_lambda_function_url", "fn", map[string]ir.Value{
		"authorization_type": ks("NONE", 3),
	})
	if fs := runRule(lambdaFunctionURLNoAuth{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test407_IAMQuiet(t *testing.T) {
	r := res("aws_lambda_function_url", "fn", map[string]ir.Value{
		"authorization_type": ks("AWS_IAM", 3),
	})
	if fs := runRule(lambdaFunctionURLNoAuth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test407_UnknownQuiet(t *testing.T) {
	r := res("aws_lambda_function_url", "fn", map[string]ir.Value{
		"authorization_type": ku(3),
	})
	if fs := runRule(lambdaFunctionURLNoAuth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 408: ECR repository policy public ---

const ecrPublicPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:BatchGetImage"}]}`

func Test408_PublicFires(t *testing.T) {
	r := res("aws_ecr_repository_policy", "p", map[string]ir.Value{
		"policy": ks(ecrPublicPolicy, 3),
	})
	if fs := runRule(ecrPolicyPublic{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test408_ScopedQuiet(t *testing.T) {
	doc := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"ecr:BatchGetImage"}}`
	r := res("aws_ecr_repository_policy", "p", map[string]ir.Value{
		"policy": ks(doc, 3),
	})
	if fs := runRule(ecrPolicyPublic{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test408_MalformedQuiet(t *testing.T) {
	r := res("aws_ecr_repository_policy", "p", map[string]ir.Value{
		"policy": ks("{not json", 3),
	})
	if fs := runRule(ecrPolicyPublic{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 409: CodePipeline webhook unauthenticated ---

func Test409_UnauthenticatedFires(t *testing.T) {
	r := res("aws_codepipeline_webhook", "wh", map[string]ir.Value{
		"authentication": ks("UNAUTHENTICATED", 3),
	})
	if fs := runRule(codePipelineWebhookUnauth{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test409_HMACQuiet(t *testing.T) {
	r := res("aws_codepipeline_webhook", "wh", map[string]ir.Value{
		"authentication": ks("GITHUB_HMAC", 3),
	})
	if fs := runRule(codePipelineWebhookUnauth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test409_UnknownQuiet(t *testing.T) {
	r := res("aws_codepipeline_webhook", "wh", map[string]ir.Value{
		"authentication": ku(3),
	})
	if fs := runRule(codePipelineWebhookUnauth{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 410: API Gateway API key hardcoded ---

func Test410_HardcodedFiresRedacted(t *testing.T) {
	r := res("aws_api_gateway_api_key", "k", map[string]ir.Value{
		"value": ks("abcdef1234567890", 3),
	})
	fs := runRule(apiGWAPIKeyHardcoded{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Evidence.Actual != "[REDACTED]" {
		t.Fatalf("secret leaked into evidence: %q", fs[0].Evidence.Actual)
	}
}

func Test410_AbsentQuiet(t *testing.T) {
	r := res("aws_api_gateway_api_key", "k", map[string]ir.Value{})
	if fs := runRule(apiGWAPIKeyHardcoded{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test410_UnknownQuiet(t *testing.T) {
	r := res("aws_api_gateway_api_key", "k", map[string]ir.Value{
		"value": ku(3),
	})
	if fs := runRule(apiGWAPIKeyHardcoded{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- Registry: ID order ---

func TestEdge2Rules_IDOrder(t *testing.T) {
	rules := Edge2Rules()
	if len(rules) != 10 {
		t.Fatalf("want 10 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := fmt.Sprintf("AEGIS-AWS-%d", 401+i)
		if r.ID() != want {
			t.Fatalf("index %d: want ID %s, got %s", i, want, r.ID())
		}
	}
}

func Test404_AbsentFires(t *testing.T) {
	// Absent authorization_type: the AWS API default is NONE (public).
	r := res("aws_apigatewayv2_route", "get", map[string]ir.Value{})
	if fs := runRule(apiGWv2RouteNoAuth{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test407_AbsentFires(t *testing.T) {
	// Absent authorization_type: the AWS API default is NONE (public URL).
	r := res("aws_lambda_function_url", "fn", map[string]ir.Value{})
	if fs := runRule(lambdaFunctionURLNoAuth{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}
