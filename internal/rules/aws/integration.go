package aws

import (
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-371: Load balancer without access logs
// ---------------------------------------------------------------------------

type lbNoAccessLogs struct{}

func (lbNoAccessLogs) ID() string { return "AEGIS-AWS-371" }
func (lbNoAccessLogs) Title() string {
	return "Load balancer without access logs"
}
func (lbNoAccessLogs) Description() string {
	return "Access logs record every request to the load balancer and are " +
		"essential for incident response and forensics. Enable them with an " +
		"access_logs block pointing at an S3 bucket."
}
func (lbNoAccessLogs) Severity() ir.Severity { return ir.SeverityMedium }

func (lbNoAccessLogs) AppliesTo(resType string) bool {
	return resType == "aws_lb" || resType == "aws_alb"
}

func (lbNoAccessLogs) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "access_logs")
	if !present {
		return lbAccessLogFinding(r, evidenceSpan(ir.Span{}, r.Span),
			"absent (provider default: disabled)")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	for _, b := range blks {
		if en, _, epresent, eknown := blockBool(b, "enabled"); epresent && eknown && en {
			return nil // at least one access_logs block enabled
		}
	}
	return lbAccessLogFinding(r, evidenceSpan(span, r.Span), "disabled")
}

func lbAccessLogFinding(r ir.Resource, span ir.Span, actual string) []ir.Finding {
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-371",
		Title:       (lbNoAccessLogs{}).Title(),
		Description: (lbNoAccessLogs{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "access_logs",
			Span:      span,
			Actual:    actual,
			Expected:  "access_logs { enabled = true }",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-372: API Gateway v2 CORS allows all origins
// ---------------------------------------------------------------------------

type apiGwV2CorsOpen struct{}

func (apiGwV2CorsOpen) ID() string { return "AEGIS-AWS-372" }
func (apiGwV2CorsOpen) Title() string {
	return "API Gateway v2 CORS allows all origins"
}
func (apiGwV2CorsOpen) Description() string {
	return "A cors_configuration with allow_origins containing \"*\" lets " +
		"any website call the API, enabling credential theft via malicious " +
		"front-ends. Restrict to explicit origins."
}
func (apiGwV2CorsOpen) Severity() ir.Severity { return ir.SeverityHigh }

func (apiGwV2CorsOpen) AppliesTo(resType string) bool {
	return resType == "aws_apigatewayv2_api"
}

func (apiGwV2CorsOpen) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "cors_configuration")
	if !present || !known {
		return nil // no CORS config, or unresolved: cannot decide
	}
	for _, b := range blks {
		origins, ok := blockStrings(b, "allow_origins")
		if !ok {
			continue // unresolved list: cannot decide
		}
		for _, o := range origins {
			if strings.TrimSpace(o) == "*" {
				v := b["allow_origins"]
				return []ir.Finding{{
					RuleID:      "AEGIS-AWS-372",
					Title:       (apiGwV2CorsOpen{}).Title(),
					Description: (apiGwV2CorsOpen{}).Description(),
					Severity:    ir.SeverityHigh,
					Resource:    r.Address(),
					Evidence: ir.Evidence{
						Attribute: "cors_configuration.allow_origins",
						Span:      evidenceSpan(v.Span, r.Span),
						Actual:    "*",
						Expected:  "explicit origin list (no \"*\")",
					},
				}}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-373: AppSync API without X-Ray tracing
// ---------------------------------------------------------------------------

type appsyncNoXray struct{}

func (appsyncNoXray) ID() string { return "AEGIS-AWS-373" }
func (appsyncNoXray) Title() string {
	return "AppSync API without X-Ray tracing"
}
func (appsyncNoXray) Description() string {
	return "X-Ray tracing gives request-level visibility into resolver " +
		"execution, which is the primary signal for detecting abuse of a " +
		"GraphQL API. Enable it with xray_enabled = true."
}
func (appsyncNoXray) Severity() ir.Severity { return ir.SeverityMedium }

func (appsyncNoXray) AppliesTo(resType string) bool {
	return resType == "aws_appsync_graphql_api"
}

func (appsyncNoXray) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "xray_enabled")
	if !present || (known && !val) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-373",
			Title:       (appsyncNoXray{}).Title(),
			Description: (appsyncNoXray{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "xray_enabled",
				Span:      evidenceSpan(span, r.Span),
				Actual:    boolActual(present, val),
				Expected:  "true",
			},
		}}
	}
	return nil // enabled, or unresolved: cannot decide
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-374: AppSync API with API-key authentication
// ---------------------------------------------------------------------------

type appsyncAPIKeyAuth struct{}

func (appsyncAPIKeyAuth) ID() string { return "AEGIS-AWS-374" }
func (appsyncAPIKeyAuth) Title() string {
	return "AppSync API with API-key authentication"
}
func (appsyncAPIKeyAuth) Description() string {
	return "API keys are long-lived shared secrets with no identity and no " +
		"rotation story. Prefer AWS_LAMBDA, OPENID_CONNECT, or " +
		"AMAZON_COGNITO_USER_POOLS authentication."
}
func (appsyncAPIKeyAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (appsyncAPIKeyAuth) AppliesTo(resType string) bool {
	return resType == "aws_appsync_graphql_api"
}

func (appsyncAPIKeyAuth) Check(r ir.Resource) []ir.Finding {
	auth, span, present, known := getString(r, "authentication_type")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(auth), "API_KEY") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-374",
		Title:       (appsyncAPIKeyAuth{}).Title(),
		Description: (appsyncAPIKeyAuth{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "authentication_type",
			Span:      evidenceSpan(span, r.Span),
			Actual:    auth,
			Expected:  "AWS_LAMBDA, OPENID_CONNECT, or AMAZON_COGNITO_USER_POOLS",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-375: EventBridge permission open to all principals
// ---------------------------------------------------------------------------

type eventBridgeOpenPermission struct{}

func (eventBridgeOpenPermission) ID() string { return "AEGIS-AWS-375" }
func (eventBridgeOpenPermission) Title() string {
	return "EventBridge permission open to all principals"
}
func (eventBridgeOpenPermission) Description() string {
	return "A cloudwatch_event_permission with principal \"*\" lets any AWS " +
		"account put events onto the bus, enabling event injection and " +
		"downstream trigger abuse. Scope the principal to specific accounts."
}
func (eventBridgeOpenPermission) Severity() ir.Severity { return ir.SeverityHigh }

func (eventBridgeOpenPermission) AppliesTo(resType string) bool {
	return resType == "aws_cloudwatch_event_permission"
}

func (eventBridgeOpenPermission) Check(r ir.Resource) []ir.Finding {
	principal, span, present, known := getString(r, "principal")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if strings.TrimSpace(principal) != "*" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-375",
		Title:       (eventBridgeOpenPermission{}).Title(),
		Description: (eventBridgeOpenPermission{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "principal",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "*",
			Expected:  "specific AWS account ID(s)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-376: Step Functions state machine without logging
// ---------------------------------------------------------------------------

type sfnNoLogging struct{}

func (sfnNoLogging) ID() string { return "AEGIS-AWS-376" }
func (sfnNoLogging) Title() string {
	return "Step Functions state machine without logging"
}
func (sfnNoLogging) Description() string {
	return "Without a logging_configuration, state machine executions leave " +
		"no CloudWatch trail, blinding incident response. Configure " +
		"logging_configuration with a log destination."
}
func (sfnNoLogging) Severity() ir.Severity { return ir.SeverityMedium }

func (sfnNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_sfn_state_machine"
}

func (sfnNoLogging) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBlocks(r, "logging_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-376",
		Title:       (sfnNoLogging{}).Title(),
		Description: (sfnNoLogging{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "logging_configuration",
			Span:      evidenceSpan(ir.Span{}, r.Span),
			Actual:    "absent (provider default: no logging)",
			Expected:  "logging_configuration with a log destination",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-377: Step Functions state machine without X-Ray tracing
// ---------------------------------------------------------------------------

type sfnNoXray struct{}

func (sfnNoXray) ID() string { return "AEGIS-AWS-377" }
func (sfnNoXray) Title() string {
	return "Step Functions state machine without X-Ray tracing"
}
func (sfnNoXray) Description() string {
	return "X-Ray tracing maps execution flow across Lambda and service " +
		"integrations, the primary signal for spotting abused workflows. " +
		"Enable it with tracing_configuration { enabled = true }."
}
func (sfnNoXray) Severity() ir.Severity { return ir.SeverityMedium }

func (sfnNoXray) AppliesTo(resType string) bool {
	return resType == "aws_sfn_state_machine"
}

func (sfnNoXray) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "tracing_configuration")
	if !present {
		return sfnXrayFinding(r, evidenceSpan(ir.Span{}, r.Span),
			"absent (provider default: disabled)")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	for _, b := range blks {
		if en, _, epresent, eknown := blockBool(b, "enabled"); epresent && eknown && en {
			return nil
		}
	}
	return sfnXrayFinding(r, evidenceSpan(span, r.Span), "disabled")
}

func sfnXrayFinding(r ir.Resource, span ir.Span, actual string) []ir.Finding {
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-377",
		Title:       (sfnNoXray{}).Title(),
		Description: (sfnNoXray{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "tracing_configuration",
			Span:      span,
			Actual:    actual,
			Expected:  "tracing_configuration { enabled = true }",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-378: WAFv2 Web ACL with default-allow and no rules
// ---------------------------------------------------------------------------

type wafv2AllowAllNoRules struct{}

func (wafv2AllowAllNoRules) ID() string { return "AEGIS-AWS-378" }
func (wafv2AllowAllNoRules) Title() string {
	return "WAFv2 Web ACL allows all traffic with no rules"
}
func (wafv2AllowAllNoRules) Description() string {
	return "A Web ACL whose default_action is allow and which defines no " +
		"rules inspects nothing: every request passes straight through. " +
		"Add managed or custom rules, or switch the default action to block."
}
func (wafv2AllowAllNoRules) Severity() ir.Severity { return ir.SeverityHigh }

func (wafv2AllowAllNoRules) AppliesTo(resType string) bool {
	return resType == "aws_wafv2_web_acl"
}

func (wafv2AllowAllNoRules) Check(r ir.Resource) []ir.Finding {
	actions, aspan, present, known := getBlocks(r, "default_action")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	allowAll := false
	for _, a := range actions {
		if v, ok := a["allow"]; ok && v.Known {
			allowAll = true
			break
		}
	}
	if !allowAll {
		return nil
	}
	// Count rule blocks: any present rule means traffic is inspected.
	rules, _, rpresent, rknown := getBlocks(r, "rule")
	if rpresent && (!rknown || len(rules) > 0) {
		return nil // rules present, or unresolved: cannot decide
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-378",
		Title:       (wafv2AllowAllNoRules{}).Title(),
		Description: (wafv2AllowAllNoRules{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "default_action",
			Span:      evidenceSpan(aspan, r.Span),
			Actual:    "allow with zero rule blocks",
			Expected:  "default_action block, or at least one rule block",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-379: Transfer server allows plaintext FTP
// ---------------------------------------------------------------------------

type transferPlaintextFTP struct{}

func (transferPlaintextFTP) ID() string { return "AEGIS-AWS-379" }
func (transferPlaintextFTP) Title() string {
	return "Transfer server allows plaintext FTP"
}
func (transferPlaintextFTP) Description() string {
	return "The FTP protocol transmits credentials and file contents in " +
		"cleartext. Restrict protocols to SFTP, FTPS, or AS2."
}
func (transferPlaintextFTP) Severity() ir.Severity { return ir.SeverityHigh }

func (transferPlaintextFTP) AppliesTo(resType string) bool {
	return resType == "aws_transfer_server"
}

func (transferPlaintextFTP) Check(r ir.Resource) []ir.Finding {
	protos, span, ok := resourceStrings(r, "protocols")
	if !ok {
		return nil // absent or unresolved: cannot decide
	}
	for _, p := range protos {
		if strings.EqualFold(strings.TrimSpace(p), "FTP") {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-379",
				Title:       (transferPlaintextFTP{}).Title(),
				Description: (transferPlaintextFTP{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "protocols",
					Span:      evidenceSpan(span, r.Span),
					Actual:    p,
					Expected:  "SFTP, FTPS, and/or AS2 only",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-380: Transfer server without CloudWatch logging
// ---------------------------------------------------------------------------

type transferNoLogging struct{}

func (transferNoLogging) ID() string { return "AEGIS-AWS-380" }
func (transferNoLogging) Title() string {
	return "Transfer server without CloudWatch logging"
}
func (transferNoLogging) Description() string {
	return "Without a logging_role the server emits no CloudWatch logs, " +
		"leaving file-transfer activity invisible to detection. Attach a " +
		"logging_role with CloudWatch permissions."
}
func (transferNoLogging) Severity() ir.Severity { return ir.SeverityMedium }

func (transferNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_transfer_server"
}

func (transferNoLogging) Check(r ir.Resource) []ir.Finding {
	role, span, present, known := getString(r, "logging_role")
	if !present || (known && strings.TrimSpace(role) == "") {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-380",
			Title:       (transferNoLogging{}).Title(),
			Description: (transferNoLogging{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "logging_role",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent (provider default: no logging)",
				Expected:  "logging_role with CloudWatch permissions",
			},
		}}
	}
	return nil // set, or unresolved: cannot decide
}

// ---------------------------------------------------------------------------
// Shared helpers (integration lane)
// ---------------------------------------------------------------------------

// boolActual is defined in compute.go and reused here.

// resourceStrings extracts a known list of strings from a top-level
// resource attribute. ok is false when the attribute is absent,
// unresolved, or not a string list.
func resourceStrings(r ir.Resource, name string) ([]string, ir.Span, bool) {
	v, ok := r.Attributes[name]
	if !ok || !v.Known {
		return nil, ir.Span{}, false
	}
	l, ok := v.AsList()
	if !ok {
		return nil, ir.Span{}, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, ir.Span{}, false
		}
		out = append(out, s)
	}
	return out, v.Span, true
}

// IntegrationRules returns the integration & edge rule set, in ID order.
func IntegrationRules() []ir.Rule {
	return []ir.Rule{
		lbNoAccessLogs{},            // AEGIS-AWS-371
		apiGwV2CorsOpen{},           // AEGIS-AWS-372
		appsyncNoXray{},             // AEGIS-AWS-373
		appsyncAPIKeyAuth{},         // AEGIS-AWS-374
		eventBridgeOpenPermission{}, // AEGIS-AWS-375
		sfnNoLogging{},              // AEGIS-AWS-376
		sfnNoXray{},                 // AEGIS-AWS-377
		wafv2AllowAllNoRules{},      // AEGIS-AWS-378
		transferPlaintextFTP{},      // AEGIS-AWS-379
		transferNoLogging{},         // AEGIS-AWS-380
	}
}
