package aws

// Lambda/serverless deep rules (AEGIS-AWS-720..739).
//
// Unknown-value contract: a present-but-unresolved attribute yields NO
// finding. Absent attributes are judged against the provider default,
// documented per rule. Rules never panic on unexpected shapes.

import (
	"encoding/json"
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// LambdaDeepRules returns the lambda/serverless deep rules, AEGIS-AWS-720..739,
// in ID order.
func LambdaDeepRules() []ir.Rule {
	return []ir.Rule{
		lambdaEventInvokeNoDestination{}, // AEGIS-AWS-720
		lambdaImageMutableTag{},          // AEGIS-AWS-721
		lambdaTimeoutLong{},              // AEGIS-AWS-722
		lambdaAliasLatestVersion{},       // AEGIS-AWS-723
		lambdaPermissionNoSourceArn{},    // AEGIS-AWS-724
		codeSigningWarnOnViolation{},     // AEGIS-AWS-725
		lambdaS3UnpinnedObject{},         // AEGIS-AWS-726
		esmNoMaxRetries{},                // AEGIS-AWS-727
		esmNoBisectOnError{},             // AEGIS-AWS-728
		sfnLoggingOff{},                  // AEGIS-AWS-729
		sfnTracingDisabled{},             // AEGIS-AWS-730
		sfnHardcodedSecrets{},            // AEGIS-AWS-731
		lambdaLayerNoRuntimes{},          // AEGIS-AWS-732
		codeSigningNoPublishers{},        // AEGIS-AWS-733
		ecsHostNamespaces{},              // AEGIS-AWS-734
		ecsContainerNoLogConfig{},        // AEGIS-AWS-735
		ecsServiceExecEnabled{},          // AEGIS-AWS-736
		ecsServiceLowHealthyPercent{},    // AEGIS-AWS-737
		eksNoAuditLog{},                  // AEGIS-AWS-738
		eksSecretsNotEncrypted{},         // AEGIS-AWS-739
	}
}

// numAttr classifies a numeric attribute into a tri-state. present=false
// means the key is absent; known=false means present but unresolved or not a
// number (undecidable).
func numAttr(r ir.Resource, name string) (float64, ir.Span, bool, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return 0, ir.Span{}, false, false
	}
	if !v.Known {
		return 0, v.Span, true, false
	}
	switch n := v.Raw.(type) {
	case float64:
		return n, v.Span, true, true
	case int:
		return float64(n), v.Span, true, true
	case int64:
		return float64(n), v.Span, true, true
	}
	return 0, v.Span, true, false
}

// blockNum extracts a numeric value from a block map (tri-state).
func blockNum(m map[string]ir.Value, name string) (float64, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return 0, ir.Span{}, false, false
	}
	if !v.Known {
		return 0, v.Span, true, false
	}
	switch n := v.Raw.(type) {
	case float64:
		return n, v.Span, true, true
	case int:
		return float64(n), v.Span, true, true
	case int64:
		return float64(n), v.Span, true, true
	}
	return 0, v.Span, true, false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-720: Lambda async invoke config without failure destination
// ---------------------------------------------------------------------------

type lambdaEventInvokeNoDestination struct{}

func (lambdaEventInvokeNoDestination) ID() string { return "AEGIS-AWS-720" }
func (lambdaEventInvokeNoDestination) Title() string {
	return "Lambda async invoke config without a failure destination"
}
func (lambdaEventInvokeNoDestination) Description() string {
	return "An aws_lambda_function_event_invoke_config without " +
		"destination_config drops failed asynchronous invocations silently: " +
		"no SQS queue, SNS topic, or EventBridge bus receives the failed " +
		"event. Add destination_config with an on_failure destination so " +
		"failures are observable and retryable."
}
func (lambdaEventInvokeNoDestination) Severity() ir.Severity { return ir.SeverityMedium }
func (lambdaEventInvokeNoDestination) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function_event_invoke_config"
}
func (lambdaEventInvokeNoDestination) Check(r ir.Resource) []ir.Finding {
	s := lambdaEventInvokeNoDestination{}
	_, _, present, known := getBlocks(r, "destination_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "destination_config",
			"absent (failed async invocations are dropped silently)",
			"destination_config { on_failure { destination = ... } }")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-721: Lambda container image with mutable tag
// ---------------------------------------------------------------------------

type lambdaImageMutableTag struct{}

func (lambdaImageMutableTag) ID() string { return "AEGIS-AWS-721" }
func (lambdaImageMutableTag) Title() string {
	return "Lambda function deployed from a mutable container image tag"
}
func (lambdaImageMutableTag) Description() string {
	return "An aws_lambda_function whose image_uri uses a mutable tag " +
		"(e.g. :latest) or no digest can silently pick up a different image " +
		"on the next update, breaking reproducibility and enabling image " +
		"substitution. Pin image_uri to an immutable digest " +
		"(image@sha256:...)."
}
func (lambdaImageMutableTag) Severity() ir.Severity { return ir.SeverityMedium }
func (lambdaImageMutableTag) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}
func (lambdaImageMutableTag) Check(r ir.Resource) []ir.Finding {
	s := lambdaImageMutableTag{}
	uri, span, present, known := getString(r, "image_uri")
	if !present || !known {
		return nil // not an image deployment or unresolved: cannot decide
	}
	u := strings.TrimSpace(uri)
	if u == "" {
		return nil
	}
	mutable := strings.Contains(u, ":latest") || !strings.Contains(u, "@")
	if !mutable {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "image_uri",
			Span:      evidenceSpan(span, r.Span),
			Actual:    u,
			Expected:  "image_uri pinned to an immutable digest (image@sha256:...)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-722: Lambda function with timeout over 5 minutes
// ---------------------------------------------------------------------------

type lambdaTimeoutLong struct{}

func (lambdaTimeoutLong) ID() string { return "AEGIS-AWS-722" }
func (lambdaTimeoutLong) Title() string {
	return "Lambda function with timeout longer than 5 minutes"
}
func (lambdaTimeoutLong) Description() string {
	return "An aws_lambda_function with timeout above 300 seconds holds " +
		"invocations (and their IAM credentials and network access) open far " +
		"longer than typical workloads need, widening the blast radius of a " +
		"compromised or hung function. Keep timeout close to the real " +
		"worst-case duration."
}
func (lambdaTimeoutLong) Severity() ir.Severity { return ir.SeverityLow }
func (lambdaTimeoutLong) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}
func (lambdaTimeoutLong) Check(r ir.Resource) []ir.Finding {
	s := lambdaTimeoutLong{}
	n, span, present, known := numAttr(r, "timeout")
	if !present || !known {
		return nil // default 3s or unresolved: cannot flag
	}
	if n <= 300 {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "timeout",
			Span:      evidenceSpan(span, r.Span),
			Actual:    strconv.FormatFloat(n, 'f', -1, 64) + " seconds",
			Expected:  "timeout of 300 seconds or less",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-723: Lambda alias pinned to $LATEST
// ---------------------------------------------------------------------------

type lambdaAliasLatestVersion struct{}

func (lambdaAliasLatestVersion) ID() string { return "AEGIS-AWS-723" }
func (lambdaAliasLatestVersion) Title() string {
	return "Lambda alias pointing at $LATEST"
}
func (lambdaAliasLatestVersion) Description() string {
	return "An aws_lambda_alias with function_version = \"$LATEST\" tracks " +
		"the mutable unpublished version, so every code update instantly " +
		"changes production traffic with no rollback point. Publish an " +
		"immutable version and point the alias at it."
}
func (lambdaAliasLatestVersion) Severity() ir.Severity { return ir.SeverityMedium }
func (lambdaAliasLatestVersion) AppliesTo(resType string) bool {
	return resType == "aws_lambda_alias"
}
func (lambdaAliasLatestVersion) Check(r ir.Resource) []ir.Finding {
	s := lambdaAliasLatestVersion{}
	ver, span, present, known := getString(r, "function_version")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if strings.TrimSpace(ver) != "$LATEST" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "function_version",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "\"$LATEST\"",
			Expected:  "an immutable published version number",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-724: Lambda permission with service principal and no source ARN
// ---------------------------------------------------------------------------

type lambdaPermissionNoSourceArn struct{}

func (lambdaPermissionNoSourceArn) ID() string { return "AEGIS-AWS-724" }
func (lambdaPermissionNoSourceArn) Title() string {
	return "Lambda permission grants a service principal without source_arn"
}
func (lambdaPermissionNoSourceArn) Description() string {
	return "An aws_lambda_permission whose principal is an AWS service " +
		"(e.g. s3.amazonaws.com) but sets no source_arn lets ANY resource of " +
		"that service in the account invoke the function. Scope the grant " +
		"with source_arn (and source_account) to the intended resource."
}
func (lambdaPermissionNoSourceArn) Severity() ir.Severity { return ir.SeverityMedium }
func (lambdaPermissionNoSourceArn) AppliesTo(resType string) bool {
	return resType == "aws_lambda_permission"
}
func (lambdaPermissionNoSourceArn) Check(r ir.Resource) []ir.Finding {
	s := lambdaPermissionNoSourceArn{}
	principal, span, present, known := getString(r, "principal")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	p := strings.TrimSpace(principal)
	if p == "" || p == "*" || !strings.HasSuffix(strings.ToLower(p), ".amazonaws.com") {
		return nil // "*" is rule 406's territory; non-service principals are fine
	}
	src, _, spresent, sknown := getString(r, "source_arn")
	if spresent && !sknown {
		return nil // unresolved: cannot decide
	}
	if spresent && strings.TrimSpace(src) != "" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "source_arn",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent (service principal " + p + " unrestricted)",
			Expected:  "source_arn scoping the grant to the intended resource",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-725: Lambda code signing warns instead of enforcing
// ---------------------------------------------------------------------------

type codeSigningWarnOnViolation struct{}

func (codeSigningWarnOnViolation) ID() string { return "AEGIS-AWS-725" }
func (codeSigningWarnOnViolation) Title() string {
	return "Lambda code signing policy warns instead of enforcing"
}
func (codeSigningWarnOnViolation) Description() string {
	return "An aws_lambda_code_signing_config whose policies set " +
		"untrusted_artifact_on_violation = \"Warn\" (the provider default) " +
		"lets unsigned or untrusted deployment packages deploy anyway. Set it " +
		"to \"Enforce\" so signature violations block deployment."
}
func (codeSigningWarnOnViolation) Severity() ir.Severity { return ir.SeverityMedium }
func (codeSigningWarnOnViolation) AppliesTo(resType string) bool {
	return resType == "aws_lambda_code_signing_config"
}
func (codeSigningWarnOnViolation) Check(r ir.Resource) []ir.Finding {
	s := codeSigningWarnOnViolation{}
	pols, _, present, known := getBlocks(r, "policies")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "policies.untrusted_artifact_on_violation",
			"absent (provider default: \"Warn\")",
			"policies { untrusted_artifact_on_violation = \"Enforce\" }")
	}
	for _, p := range pols {
		v, span, vpresent, vknown := blockString(p, "untrusted_artifact_on_violation")
		if vpresent && !vknown {
			return nil // unresolved: cannot decide
		}
		if !vpresent {
			return absentInsecureDefault(s, r, "policies.untrusted_artifact_on_violation",
				"absent (provider default: \"Warn\")",
				"untrusted_artifact_on_violation = \"Enforce\"")
		}
		if strings.EqualFold(strings.TrimSpace(v), "Enforce") {
			return nil
		}
		return []ir.Finding{{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policies.untrusted_artifact_on_violation",
				Span:      evidenceSpan(span, r.Span),
				Actual:    v,
				Expected:  "\"Enforce\"",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-726: Lambda S3 deployment without pinned object version
// ---------------------------------------------------------------------------

type lambdaS3UnpinnedObject struct{}

func (lambdaS3UnpinnedObject) ID() string { return "AEGIS-AWS-726" }
func (lambdaS3UnpinnedObject) Title() string {
	return "Lambda function deployed from an unpinned S3 object version"
}
func (lambdaS3UnpinnedObject) Description() string {
	return "An aws_lambda_function deployed from s3_bucket/s3_key without " +
		"s3_object_version silently picks up a different deployment package " +
		"whenever the S3 object is overwritten, breaking reproducibility and " +
		"auditability. Pin s3_object_version to an immutable version ID."
}
func (lambdaS3UnpinnedObject) Severity() ir.Severity { return ir.SeverityLow }
func (lambdaS3UnpinnedObject) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}
func (lambdaS3UnpinnedObject) Check(r ir.Resource) []ir.Finding {
	s := lambdaS3UnpinnedObject{}
	bucket, _, present, known := getString(r, "s3_bucket")
	if !present || !known || strings.TrimSpace(bucket) == "" {
		return nil // not an S3 deployment or unresolved: cannot decide
	}
	_, _, vpresent, vknown := getString(r, "s3_object_version")
	if vpresent && !vknown {
		return nil // unresolved: cannot decide
	}
	if vpresent {
		return nil
	}
	return absentInsecureDefault(s, r, "s3_object_version",
		"absent (tracks the mutable current object version)",
		"s3_object_version pinned to an immutable version ID")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-727: Lambda event source mapping without retry limit
// ---------------------------------------------------------------------------

type esmNoMaxRetries struct{}

func (esmNoMaxRetries) ID() string { return "AEGIS-AWS-727" }
func (esmNoMaxRetries) Title() string {
	return "Lambda event source mapping without a retry limit"
}
func (esmNoMaxRetries) Description() string {
	return "An aws_lambda_event_source_mapping without maximum_retry_attempts " +
		"falls back to the provider default (-1: infinite retries for SQS), " +
		"so a poison-pill message is retried forever, burning invocations " +
		"and delaying the dead-letter queue. Set an explicit " +
		"maximum_retry_attempts."
}
func (esmNoMaxRetries) Severity() ir.Severity { return ir.SeverityLow }
func (esmNoMaxRetries) AppliesTo(resType string) bool {
	return resType == "aws_lambda_event_source_mapping"
}
func (esmNoMaxRetries) Check(r ir.Resource) []ir.Finding {
	s := esmNoMaxRetries{}
	_, _, present, known := numAttr(r, "maximum_retry_attempts")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "maximum_retry_attempts",
			"absent (provider default: -1, infinite retries)",
			"maximum_retry_attempts set to a finite value")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-728: Lambda event source mapping without batch bisect on error
// ---------------------------------------------------------------------------

type esmNoBisectOnError struct{}

func (esmNoBisectOnError) ID() string { return "AEGIS-AWS-728" }
func (esmNoBisectOnError) Title() string {
	return "Lambda event source mapping without bisect on batch error"
}
func (esmNoBisectOnError) Description() string {
	return "An aws_lambda_event_source_mapping with " +
		"bisect_batch_on_function_error disabled (the provider default) " +
		"reprocesses the whole batch when one record fails, so a single " +
		"poison record blocks the entire shard. Enable " +
		"bisect_batch_on_function_error for stream sources."
}
func (esmNoBisectOnError) Severity() ir.Severity { return ir.SeverityLow }
func (esmNoBisectOnError) AppliesTo(resType string) bool {
	return resType == "aws_lambda_event_source_mapping"
}
func (esmNoBisectOnError) Check(r ir.Resource) []ir.Finding {
	s := esmNoBisectOnError{}
	val, span, present, known := getBool(r, "bisect_batch_on_function_error")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "bisect_batch_on_function_error",
			"absent (provider default: false)",
			"bisect_batch_on_function_error = true")
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
			Attribute: "bisect_batch_on_function_error",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-729: Step Functions state machine with logging switched off
// ---------------------------------------------------------------------------

type sfnLoggingOff struct{}

func (sfnLoggingOff) ID() string { return "AEGIS-AWS-729" }
func (sfnLoggingOff) Title() string {
	return "Step Functions state machine with logging switched off"
}
func (sfnLoggingOff) Description() string {
	return "An aws_sfn_state_machine whose logging_configuration sets " +
		"level = \"OFF\" explicitly disables execution logging, blinding " +
		"incident response to workflow activity. Set level to ALL, ERROR, or " +
		"FATAL with a CloudWatch log destination."
}
func (sfnLoggingOff) Severity() ir.Severity { return ir.SeverityMedium }
func (sfnLoggingOff) AppliesTo(resType string) bool {
	return resType == "aws_sfn_state_machine"
}
func (sfnLoggingOff) Check(r ir.Resource) []ir.Finding {
	s := sfnLoggingOff{}
	cfgs, _, present, known := getBlocks(r, "logging_configuration")
	if !present || !known {
		return nil // absent is rule 376's territory; unresolved: cannot decide
	}
	for _, c := range cfgs {
		lvl, span, lpresent, lknown := blockString(c, "level")
		if lpresent && !lknown {
			return nil // unresolved: cannot decide
		}
		if lpresent && strings.EqualFold(strings.TrimSpace(lvl), "OFF") {
			return []ir.Finding{{
				RuleID:      s.ID(),
				Title:       s.Title(),
				Description: s.Description(),
				Severity:    s.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "logging_configuration.level",
					Span:      evidenceSpan(span, r.Span),
					Actual:    lvl,
					Expected:  "\"ALL\", \"ERROR\", or \"FATAL\"",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-730: Step Functions state machine with tracing disabled
// ---------------------------------------------------------------------------

type sfnTracingDisabled struct{}

func (sfnTracingDisabled) ID() string { return "AEGIS-AWS-730" }
func (sfnTracingDisabled) Title() string {
	return "Step Functions state machine with X-Ray tracing disabled"
}
func (sfnTracingDisabled) Description() string {
	return "An aws_sfn_state_machine whose tracing_configuration sets " +
		"enabled = false explicitly disables X-Ray tracing, losing " +
		"distributed visibility into workflow executions. Enable tracing " +
		"with tracing_configuration { enabled = true }."
}
func (sfnTracingDisabled) Severity() ir.Severity { return ir.SeverityLow }
func (sfnTracingDisabled) AppliesTo(resType string) bool {
	return resType == "aws_sfn_state_machine"
}
func (sfnTracingDisabled) Check(r ir.Resource) []ir.Finding {
	s := sfnTracingDisabled{}
	cfgs, _, present, known := getBlocks(r, "tracing_configuration")
	if !present || !known {
		return nil // absent is another rule's territory; unresolved: cannot decide
	}
	for _, c := range cfgs {
		en, span, epresent, eknown := blockBool(c, "enabled")
		if epresent && !eknown {
			return nil // unresolved: cannot decide
		}
		if epresent && !en {
			return []ir.Finding{{
				RuleID:      s.ID(),
				Title:       s.Title(),
				Description: s.Description(),
				Severity:    s.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "tracing_configuration.enabled",
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
// AEGIS-AWS-731: Step Functions definition with hardcoded password
// ---------------------------------------------------------------------------

type sfnHardcodedSecrets struct{}

func (sfnHardcodedSecrets) ID() string { return "AEGIS-AWS-731" }
func (sfnHardcodedSecrets) Title() string {
	return "Step Functions definition contains a hardcoded password"
}
func (sfnHardcodedSecrets) Description() string {
	return "An aws_sfn_state_machine whose definition string contains a " +
		"hardcoded password embeds a credential in the state machine " +
		"definition, visible in the console, CloudTrail, and Terraform " +
		"state. Reference secrets from Secrets Manager or SSM Parameter " +
		"Store instead."
}
func (sfnHardcodedSecrets) Severity() ir.Severity { return ir.SeverityHigh }
func (sfnHardcodedSecrets) AppliesTo(resType string) bool {
	return resType == "aws_sfn_state_machine"
}
func (sfnHardcodedSecrets) Check(r ir.Resource) []ir.Finding {
	s := sfnHardcodedSecrets{}
	def, span, present, known := getString(r, "definition")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if !strings.Contains(strings.ToLower(def), "password") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "definition",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "definition contains a hardcoded \"password\" value",
			Expected:  "credentials referenced from Secrets Manager or SSM Parameter Store",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-732: Lambda layer without compatible runtimes
// ---------------------------------------------------------------------------

type lambdaLayerNoRuntimes struct{}

func (lambdaLayerNoRuntimes) ID() string { return "AEGIS-AWS-732" }
func (lambdaLayerNoRuntimes) Title() string {
	return "Lambda layer version without compatible runtimes"
}
func (lambdaLayerNoRuntimes) Description() string {
	return "An aws_lambda_layer_version without compatible_runtimes can be " +
		"attached to a function running any runtime, including ones the " +
		"layer was never built or tested for, risking breakage or loading " +
		"unvetted native code. Declare the runtimes the layer supports."
}
func (lambdaLayerNoRuntimes) Severity() ir.Severity { return ir.SeverityLow }
func (lambdaLayerNoRuntimes) AppliesTo(resType string) bool {
	return resType == "aws_lambda_layer_version"
}
func (lambdaLayerNoRuntimes) Check(r ir.Resource) []ir.Finding {
	s := lambdaLayerNoRuntimes{}
	v, ok := r.Attributes["compatible_runtimes"]
	if !ok {
		return absentInsecureDefault(s, r, "compatible_runtimes",
			"absent (layer attachable to any runtime)",
			"compatible_runtimes listing the supported runtimes")
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-733: Lambda code signing config without allowed publishers
// ---------------------------------------------------------------------------

type codeSigningNoPublishers struct{}

func (codeSigningNoPublishers) ID() string { return "AEGIS-AWS-733" }
func (codeSigningNoPublishers) Title() string {
	return "Lambda code signing config without allowed publishers"
}
func (codeSigningNoPublishers) Description() string {
	return "An aws_lambda_code_signing_config without an allowed_publishers " +
		"block does not restrict which signing profiles may sign deployment " +
		"packages, weakening the provenance guarantee code signing is meant " +
		"to provide. Pin allowed_publishers to the expected signing profile " +
		"version ARNs."
}
func (codeSigningNoPublishers) Severity() ir.Severity { return ir.SeverityLow }
func (codeSigningNoPublishers) AppliesTo(resType string) bool {
	return resType == "aws_lambda_code_signing_config"
}
func (codeSigningNoPublishers) Check(r ir.Resource) []ir.Finding {
	s := codeSigningNoPublishers{}
	_, _, present, known := getBlocks(r, "allowed_publishers")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(s, r, "allowed_publishers",
			"absent (no publisher restriction)",
			"allowed_publishers { signing_profile_version_arns = [...] }")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-734: ECS task definition sharing host namespaces
// ---------------------------------------------------------------------------

type ecsHostNamespaces struct{}

func (ecsHostNamespaces) ID() string { return "AEGIS-AWS-734" }
func (ecsHostNamespaces) Title() string {
	return "ECS task definition sharing host PID or IPC namespace"
}
func (ecsHostNamespaces) Description() string {
	return "An aws_ecs_task_definition with pid_mode or ipc_mode = \"host\" " +
		"shares the host's process or IPC namespace with every container in " +
		"the task, letting a compromised container inspect or signal host " +
		"processes. Keep the default task-scoped namespaces."
}
func (ecsHostNamespaces) Severity() ir.Severity { return ir.SeverityHigh }
func (ecsHostNamespaces) AppliesTo(resType string) bool {
	return resType == "aws_ecs_task_definition"
}
func (ecsHostNamespaces) Check(r ir.Resource) []ir.Finding {
	s := ecsHostNamespaces{}
	for _, attr := range []string{"pid_mode", "ipc_mode"} {
		mode, span, present, known := getString(r, attr)
		if present && !known {
			return nil // unresolved: cannot decide
		}
		if present && strings.EqualFold(strings.TrimSpace(mode), "host") {
			return []ir.Finding{{
				RuleID:      s.ID(),
				Title:       s.Title(),
				Description: s.Description(),
				Severity:    s.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: attr,
					Span:      evidenceSpan(span, r.Span),
					Actual:    mode,
					Expected:  "\"task\" (default task-scoped namespace)",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-735: ECS container without log configuration
// ---------------------------------------------------------------------------

type ecsContainerNoLogConfig struct{}

func (ecsContainerNoLogConfig) ID() string { return "AEGIS-AWS-735" }
func (ecsContainerNoLogConfig) Title() string {
	return "ECS container without log configuration"
}
func (ecsContainerNoLogConfig) Description() string {
	return "A container in aws_ecs_task_definition's container_definitions " +
		"without logConfiguration sends stdout/stderr only to the Docker " +
		"daemon log, which is ephemeral and invisible to CloudWatch. Add a " +
		"logConfiguration with the awslogs driver so container output is " +
		"centralized and auditable."
}
func (ecsContainerNoLogConfig) Severity() ir.Severity { return ir.SeverityMedium }
func (ecsContainerNoLogConfig) AppliesTo(resType string) bool {
	return resType == "aws_ecs_task_definition"
}
func (ecsContainerNoLogConfig) Check(r ir.Resource) []ir.Finding {
	s := ecsContainerNoLogConfig{}
	raw, span, present, known := getString(r, "container_definitions")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	var defs []map[string]any
	if err := json.Unmarshal([]byte(raw), &defs); err != nil {
		return nil // unparseable JSON: cannot decide
	}
	for _, d := range defs {
		lc, ok := d["logConfiguration"].(map[string]any)
		if !ok {
			name, _ := d["name"].(string)
			detail := "a container"
			if name != "" {
				detail = "container " + name
			}
			return []ir.Finding{{
				RuleID:      s.ID(),
				Title:       s.Title(),
				Description: s.Description(),
				Severity:    s.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "container_definitions[].logConfiguration",
					Span:      evidenceSpan(span, r.Span),
					Actual:    detail + " has no logConfiguration",
					Expected:  "logConfiguration with the awslogs driver",
				},
			}}
		}
		if drv, _ := lc["logDriver"].(string); strings.TrimSpace(drv) == "" {
			name, _ := d["name"].(string)
			detail := "a container"
			if name != "" {
				detail = "container " + name
			}
			return []ir.Finding{{
				RuleID:      s.ID(),
				Title:       s.Title(),
				Description: s.Description(),
				Severity:    s.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "container_definitions[].logConfiguration.logDriver",
					Span:      evidenceSpan(span, r.Span),
					Actual:    detail + " has no logDriver",
					Expected:  "logDriver = \"awslogs\"",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-736: ECS service with ECS Exec enabled
// ---------------------------------------------------------------------------

type ecsServiceExecEnabled struct{}

func (ecsServiceExecEnabled) ID() string { return "AEGIS-AWS-736" }
func (ecsServiceExecEnabled) Title() string {
	return "ECS service with ECS Exec enabled"
}
func (ecsServiceExecEnabled) Description() string {
	return "An aws_ecs_service with enable_execute_command = true opens an " +
		"interactive shell into running containers via SSM, bypassing normal " +
		"access controls and leaving exec sessions in the audit trail only " +
		"if logging is configured. Disable it unless interactive debugging " +
		"is actively needed."
}
func (ecsServiceExecEnabled) Severity() ir.Severity { return ir.SeverityMedium }
func (ecsServiceExecEnabled) AppliesTo(resType string) bool {
	return resType == "aws_ecs_service"
}
func (ecsServiceExecEnabled) Check(r ir.Resource) []ir.Finding {
	s := ecsServiceExecEnabled{}
	val, span, present, known := getBool(r, "enable_execute_command")
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
			Attribute: "enable_execute_command",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (or omitted)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-737: ECS service allowing downtime during deployments
// ---------------------------------------------------------------------------

type ecsServiceLowHealthyPercent struct{}

func (ecsServiceLowHealthyPercent) ID() string { return "AEGIS-AWS-737" }
func (ecsServiceLowHealthyPercent) Title() string {
	return "ECS service allowing downtime during deployments"
}
func (ecsServiceLowHealthyPercent) Description() string {
	return "An aws_ecs_service with deployment_minimum_healthy_percent below " +
		"100 lets a deployment stop healthy tasks before replacements are " +
		"running, causing downtime and giving a bad deploy a window with no " +
		"healthy capacity. Keep it at 100 for rolling deployments."
}
func (ecsServiceLowHealthyPercent) Severity() ir.Severity { return ir.SeverityLow }
func (ecsServiceLowHealthyPercent) AppliesTo(resType string) bool {
	return resType == "aws_ecs_service"
}
func (ecsServiceLowHealthyPercent) Check(r ir.Resource) []ir.Finding {
	s := ecsServiceLowHealthyPercent{}
	n, span, present, known := numAttr(r, "deployment_minimum_healthy_percent")
	if !present || !known {
		return nil // default 100 or unresolved: cannot flag
	}
	if n >= 100 {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "deployment_minimum_healthy_percent",
			Span:      evidenceSpan(span, r.Span),
			Actual:    strconv.FormatFloat(n, 'f', -1, 64),
			Expected:  "100",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-738: EKS cluster logging without the audit log type
// ---------------------------------------------------------------------------

type eksNoAuditLog struct{}

func (eksNoAuditLog) ID() string { return "AEGIS-AWS-738" }
func (eksNoAuditLog) Title() string {
	return "EKS cluster control plane logging without audit logs"
}
func (eksNoAuditLog) Description() string {
	return "An aws_eks_cluster with enabled_cluster_log_types set but " +
		"missing \"audit\" ships control plane logs without the Kubernetes " +
		"audit stream, losing the record of who did what to the cluster. " +
		"Include \"audit\" in enabled_cluster_log_types."
}
func (eksNoAuditLog) Severity() ir.Severity { return ir.SeverityHigh }
func (eksNoAuditLog) AppliesTo(resType string) bool {
	return resType == "aws_eks_cluster"
}
func (eksNoAuditLog) Check(r ir.Resource) []ir.Finding {
	s := eksNoAuditLog{}
	v, ok := r.Attributes["enabled_cluster_log_types"]
	if !ok || !v.Known {
		return nil // absent/empty is rule 306's territory; unresolved: cannot decide
	}
	l, ok := v.AsList()
	if !ok || len(l) == 0 {
		return nil
	}
	types := make([]string, 0, len(l))
	allKnown := true
	for _, item := range l {
		t, kok := item.AsString()
		if !kok {
			allKnown = false
			break
		}
		types = append(types, t)
	}
	if !allKnown {
		return nil // unresolved element: cannot decide
	}
	if findStringFold(types, "audit") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      s.ID(),
		Title:       s.Title(),
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enabled_cluster_log_types",
			Span:      evidenceSpan(v.Span, r.Span),
			Actual:    "[" + strings.Join(types, ", ") + "] (no \"audit\")",
			Expected:  "list including \"audit\"",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-739: EKS encryption config not covering secrets
// ---------------------------------------------------------------------------

type eksSecretsNotEncrypted struct{}

func (eksSecretsNotEncrypted) ID() string { return "AEGIS-AWS-739" }
func (eksSecretsNotEncrypted) Title() string {
	return "EKS encryption config not covering Kubernetes secrets"
}
func (eksSecretsNotEncrypted) Description() string {
	return "An aws_eks_cluster with encryption_config that does not list " +
		"\"secrets\" in resources leaves Kubernetes Secrets encrypted only " +
		"with the AWS-owned key (or unencrypted at rest in etcd), instead of " +
		"the intended KMS key. Include \"secrets\" in the encrypted " +
		"resources."
}
func (eksSecretsNotEncrypted) Severity() ir.Severity { return ir.SeverityHigh }
func (eksSecretsNotEncrypted) AppliesTo(resType string) bool {
	return resType == "aws_eks_cluster"
}
func (eksSecretsNotEncrypted) Check(r ir.Resource) []ir.Finding {
	s := eksSecretsNotEncrypted{}
	cfgs, _, present, known := getBlocks(r, "encryption_config")
	if !present || !known {
		return nil // absent is rule 304's territory; unresolved: cannot decide
	}
	for _, c := range cfgs {
		resList, ok := c["resources"]
		if !ok || !resList.Known {
			return nil // unresolved: cannot decide
		}
		l, ok := resList.AsList()
		if !ok {
			return nil // unexpected shape: cannot decide
		}
		strs := make([]string, 0, len(l))
		allKnown := true
		for _, item := range l {
			t, kok := item.AsString()
			if !kok {
				allKnown = false
				break
			}
			strs = append(strs, t)
		}
		if !allKnown {
			return nil
		}
		if findStringFold(strs, "secrets") {
			return nil
		}
		return []ir.Finding{{
			RuleID:      s.ID(),
			Title:       s.Title(),
			Description: s.Description(),
			Severity:    s.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "encryption_config.resources",
				Span:      evidenceSpan(resList.Span, r.Span),
				Actual:    "[" + strings.Join(strs, ", ") + "] (no \"secrets\")",
				Expected:  "resources including \"secrets\"",
			},
		}}
	}
	return nil
}
