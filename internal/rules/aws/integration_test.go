package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// 371: LB without access logs
// ---------------------------------------------------------------------------

func Test371_AbsentFires(t *testing.T) {
	fs := runRule(lbNoAccessLogs{}, res("aws_lb", "web", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test371_DisabledFires(t *testing.T) {
	fs := runRule(lbNoAccessLogs{}, res("aws_alb", "web", map[string]ir.Value{
		"access_logs": blks(4, blk("enabled", kv(false, 5))),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test371_EnabledQuiet(t *testing.T) {
	fs := runRule(lbNoAccessLogs{}, res("aws_lb", "web", map[string]ir.Value{
		"access_logs": blks(4, blk("enabled", kv(true, 5), "bucket", ks("logs", 6))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test371_UnknownQuiet(t *testing.T) {
	fs := runRule(lbNoAccessLogs{}, res("aws_lb", "web", map[string]ir.Value{
		"access_logs": ku(3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 372: API Gateway v2 CORS allows all origins
// ---------------------------------------------------------------------------

func Test372_WildcardFires(t *testing.T) {
	fs := runRule(apiGwV2CorsOpen{}, res("aws_apigatewayv2_api", "api", map[string]ir.Value{
		"cors_configuration": blks(4, blk("allow_origins", strList(5, "https://app.example.com", "*"))),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high severity, got %s", fs[0].Severity)
	}
}

func Test372_SpecificOriginsQuiet(t *testing.T) {
	fs := runRule(apiGwV2CorsOpen{}, res("aws_apigatewayv2_api", "api", map[string]ir.Value{
		"cors_configuration": blks(4, blk("allow_origins", strList(5, "https://app.example.com"))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test372_NoCorsQuiet(t *testing.T) {
	fs := runRule(apiGwV2CorsOpen{}, res("aws_apigatewayv2_api", "api", map[string]ir.Value{}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test372_UnknownOriginsQuiet(t *testing.T) {
	fs := runRule(apiGwV2CorsOpen{}, res("aws_apigatewayv2_api", "api", map[string]ir.Value{
		"cors_configuration": blks(4, blk("allow_origins", ku(5))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 373: AppSync without X-Ray
// ---------------------------------------------------------------------------

func Test373_AbsentFires(t *testing.T) {
	fs := runRule(appsyncNoXray{}, res("aws_appsync_graphql_api", "api", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test373_DisabledFires(t *testing.T) {
	fs := runRule(appsyncNoXray{}, res("aws_appsync_graphql_api", "api", map[string]ir.Value{
		"xray_enabled": kv(false, 3),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test373_EnabledQuiet(t *testing.T) {
	fs := runRule(appsyncNoXray{}, res("aws_appsync_graphql_api", "api", map[string]ir.Value{
		"xray_enabled": kv(true, 3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test373_UnknownQuiet(t *testing.T) {
	fs := runRule(appsyncNoXray{}, res("aws_appsync_graphql_api", "api", map[string]ir.Value{
		"xray_enabled": ku(3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 374: AppSync API-key auth
// ---------------------------------------------------------------------------

func Test374_APIKeyFires(t *testing.T) {
	fs := runRule(appsyncAPIKeyAuth{}, res("aws_appsync_graphql_api", "api", map[string]ir.Value{
		"authentication_type": ks("API_KEY", 3),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test374_CognitoQuiet(t *testing.T) {
	fs := runRule(appsyncAPIKeyAuth{}, res("aws_appsync_graphql_api", "api", map[string]ir.Value{
		"authentication_type": ks("AMAZON_COGNITO_USER_POOLS", 3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test374_UnknownQuiet(t *testing.T) {
	fs := runRule(appsyncAPIKeyAuth{}, res("aws_appsync_graphql_api", "api", map[string]ir.Value{
		"authentication_type": ku(3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 375: EventBridge permission open to all
// ---------------------------------------------------------------------------

func Test375_StarFires(t *testing.T) {
	fs := runRule(eventBridgeOpenPermission{}, res("aws_cloudwatch_event_permission", "open", map[string]ir.Value{
		"principal": ks("*", 3),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high severity, got %s", fs[0].Severity)
	}
}

func Test375_ScopedQuiet(t *testing.T) {
	fs := runRule(eventBridgeOpenPermission{}, res("aws_cloudwatch_event_permission", "scoped", map[string]ir.Value{
		"principal": ks("123456789012", 3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test375_UnknownQuiet(t *testing.T) {
	fs := runRule(eventBridgeOpenPermission{}, res("aws_cloudwatch_event_permission", "x", map[string]ir.Value{
		"principal": ku(3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 376: Step Functions without logging
// ---------------------------------------------------------------------------

func Test376_AbsentFires(t *testing.T) {
	fs := runRule(sfnNoLogging{}, res("aws_sfn_state_machine", "sm", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test376_PresentQuiet(t *testing.T) {
	fs := runRule(sfnNoLogging{}, res("aws_sfn_state_machine", "sm", map[string]ir.Value{
		"logging_configuration": blks(4, blk("log_destination", ks("arn:aws:logs:us-east-1:1:log-group:sm", 5))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test376_UnknownQuiet(t *testing.T) {
	fs := runRule(sfnNoLogging{}, res("aws_sfn_state_machine", "sm", map[string]ir.Value{
		"logging_configuration": ku(4),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 377: Step Functions without X-Ray
// ---------------------------------------------------------------------------

func Test377_AbsentFires(t *testing.T) {
	fs := runRule(sfnNoXray{}, res("aws_sfn_state_machine", "sm", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test377_DisabledFires(t *testing.T) {
	fs := runRule(sfnNoXray{}, res("aws_sfn_state_machine", "sm", map[string]ir.Value{
		"tracing_configuration": blks(4, blk("enabled", kv(false, 5))),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test377_EnabledQuiet(t *testing.T) {
	fs := runRule(sfnNoXray{}, res("aws_sfn_state_machine", "sm", map[string]ir.Value{
		"tracing_configuration": blks(4, blk("enabled", kv(true, 5))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test377_UnknownQuiet(t *testing.T) {
	fs := runRule(sfnNoXray{}, res("aws_sfn_state_machine", "sm", map[string]ir.Value{
		"tracing_configuration": ku(4),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 378: WAFv2 default-allow with no rules
// ---------------------------------------------------------------------------

func wafAllowAction(line int) map[string]ir.Value {
	return blk("allow", ir.Value{Raw: map[string]ir.Value{}, Known: true, Span: spanAt(line)})
}

func Test378_AllowNoRulesFires(t *testing.T) {
	fs := runRule(wafv2AllowAllNoRules{}, res("aws_wafv2_web_acl", "acl", map[string]ir.Value{
		"default_action": blks(4, wafAllowAction(5)),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high severity, got %s", fs[0].Severity)
	}
}

func Test378_AllowWithRulesQuiet(t *testing.T) {
	fs := runRule(wafv2AllowAllNoRules{}, res("aws_wafv2_web_acl", "acl", map[string]ir.Value{
		"default_action": blks(4, wafAllowAction(5)),
		"rule":           blks(6, blk("name", ks("AWSManagedRulesCommonRuleSet", 7))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test378_BlockDefaultQuiet(t *testing.T) {
	fs := runRule(wafv2AllowAllNoRules{}, res("aws_wafv2_web_acl", "acl", map[string]ir.Value{
		"default_action": blks(4, blk("block", ir.Value{Raw: map[string]ir.Value{}, Known: true, Span: spanAt(5)})),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test378_UnknownActionQuiet(t *testing.T) {
	fs := runRule(wafv2AllowAllNoRules{}, res("aws_wafv2_web_acl", "acl", map[string]ir.Value{
		"default_action": ku(4),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 379: Transfer server plaintext FTP
// ---------------------------------------------------------------------------

func Test379_FTPFires(t *testing.T) {
	fs := runRule(transferPlaintextFTP{}, res("aws_transfer_server", "s", map[string]ir.Value{
		"protocols": strList(3, "SFTP", "ftp"),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test379_SFTPOnlyQuiet(t *testing.T) {
	fs := runRule(transferPlaintextFTP{}, res("aws_transfer_server", "s", map[string]ir.Value{
		"protocols": strList(3, "SFTP", "FTPS"),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test379_UnknownProtocolsQuiet(t *testing.T) {
	fs := runRule(transferPlaintextFTP{}, res("aws_transfer_server", "s", map[string]ir.Value{
		"protocols": ku(3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// 380: Transfer server without logging
// ---------------------------------------------------------------------------

func Test380_AbsentFires(t *testing.T) {
	fs := runRule(transferNoLogging{}, res("aws_transfer_server", "s", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test380_EmptyFires(t *testing.T) {
	fs := runRule(transferNoLogging{}, res("aws_transfer_server", "s", map[string]ir.Value{
		"logging_role": ks("  ", 3),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test380_SetQuiet(t *testing.T) {
	fs := runRule(transferNoLogging{}, res("aws_transfer_server", "s", map[string]ir.Value{
		"logging_role": ks("arn:aws:iam::1:role/transfer-logs", 3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test380_UnknownQuiet(t *testing.T) {
	fs := runRule(transferNoLogging{}, res("aws_transfer_server", "s", map[string]ir.Value{
		"logging_role": ku(3),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// Registry order guard
// ---------------------------------------------------------------------------

func TestIntegrationRules_IDOrder(t *testing.T) {
	rules := IntegrationRules()
	want := []string{
		"AEGIS-AWS-371", "AEGIS-AWS-372", "AEGIS-AWS-373", "AEGIS-AWS-374",
		"AEGIS-AWS-375", "AEGIS-AWS-376", "AEGIS-AWS-377", "AEGIS-AWS-378",
		"AEGIS-AWS-379", "AEGIS-AWS-380",
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Fatalf("position %d: got %s, want %s", i, r.ID(), want[i])
		}
	}
}
