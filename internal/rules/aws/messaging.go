// Package aws — messaging & monitoring rules (AEGIS-AWS-341..350).
//
// SNS/SQS/MSK/Kinesis encryption, topic/queue policy exposure, CloudWatch
// log-group hardening, GuardDuty, and MQ broker encryption.
package aws

import (
	"strings"

	"aegis/internal/ir"
)

// MessagingRules returns the messaging & monitoring rules in ID order.
// Wired into the pack by the parent; do not duplicate registration.
func MessagingRules() []ir.Rule {
	return []ir.Rule{
		snsNoKMS{},            // AEGIS-AWS-341
		sqsNoEncryption{},     // AEGIS-AWS-342
		snsPolicyPublic{},     // AEGIS-AWS-343
		sqsPolicyPublic{},     // AEGIS-AWS-344
		mskNoEncryption{},     // AEGIS-AWS-345
		cwLogGroupNoKMS{},     // AEGIS-AWS-346
		cwLogGroupNoRetain{},  // AEGIS-AWS-347
		guardDutyDisabled{},   // AEGIS-AWS-348
		mqBrokerNoCMK{},       // AEGIS-AWS-349
		kinesisNoEncryption{}, // AEGIS-AWS-350
	}
}

// finding is a small helper to build single-resource findings uniformly.
func msgFinding(rule ir.Rule, r ir.Resource, attr string, span ir.Span, actual, expected string) []ir.Finding {
	return []ir.Finding{{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-341: SNS topic without KMS encryption
// ---------------------------------------------------------------------------

type snsNoKMS struct{}

func (snsNoKMS) ID() string    { return "AEGIS-AWS-341" }
func (snsNoKMS) Title() string { return "SNS topic without KMS encryption" }
func (snsNoKMS) Description() string {
	return "SNS topics should encrypt messages at rest with a KMS key. " +
		"A topic with no kms_master_key_id relies on unencrypted delivery."
}
func (snsNoKMS) Severity() ir.Severity { return ir.SeverityHigh }

func (snsNoKMS) AppliesTo(resType string) bool { return resType == "aws_sns_topic" }

func (snsNoKMS) Check(r ir.Resource) []ir.Finding {
	rule := snsNoKMS{}
	key, span, present, known := getString(r, "kms_master_key_id")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || strings.TrimSpace(key) == "" {
		return msgFinding(rule, r, "kms_master_key_id", span,
			"absent", "kms_master_key_id set to a KMS key ARN or alias")
	}
	return nil // any key set (including alias/aws/sns) counts as encrypted
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-342: SQS queue without encryption
// ---------------------------------------------------------------------------

type sqsNoEncryption struct{}

func (sqsNoEncryption) ID() string    { return "AEGIS-AWS-342" }
func (sqsNoEncryption) Title() string { return "SQS queue without encryption" }
func (sqsNoEncryption) Description() string {
	return "SQS queues should encrypt messages at rest (SSE-SQS via " +
		"sqs_managed_sse_enabled or SSE-KMS via kms_master_key_id). A queue " +
		"with SSE-SQS explicitly disabled and no KMS key stores plaintext. " +
		"Note: modern provider defaults enable SSE-SQS, so an absent " +
		"sqs_managed_sse_enabled is treated as enabled (no finding)."
}
func (sqsNoEncryption) Severity() ir.Severity { return ir.SeverityHigh }

func (sqsNoEncryption) AppliesTo(resType string) bool { return resType == "aws_sqs_queue" }

func (sqsNoEncryption) Check(r ir.Resource) []ir.Finding {
	rule := sqsNoEncryption{}
	// SSE-KMS set to any key silences the rule.
	key, _, present, known := getString(r, "kms_master_key_id")
	if present {
		if !known {
			return nil // unresolved: cannot decide
		}
		if strings.TrimSpace(key) != "" {
			return nil // SSE-KMS configured
		}
	}
	managed, _, mpresent, mknown := getBool(r, "sqs_managed_sse_enabled")
	if !mpresent {
		return nil // absent: modern provider default is SSE-SQS enabled
	}
	if !mknown {
		return nil // unresolved: cannot decide
	}
	if managed {
		return nil // SSE-SQS enabled
	}
	return msgFinding(rule, r, "sqs_managed_sse_enabled", ir.Span{},
		"sqs_managed_sse_enabled = false with no kms_master_key_id",
		"sqs_managed_sse_enabled = true or a kms_master_key_id set")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-343: SNS topic policy allows public principal
// AEGIS-AWS-344: SQS queue policy allows public principal
// ---------------------------------------------------------------------------

type snsPolicyPublic struct{}

func (snsPolicyPublic) ID() string    { return "AEGIS-AWS-343" }
func (snsPolicyPublic) Title() string { return "SNS topic policy allows public principal" }
func (snsPolicyPublic) Description() string {
	return "A topic policy Allow statement with Principal \"*\" grants " +
		"anonymous publish/subscribe access to the topic."
}
func (snsPolicyPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (snsPolicyPublic) AppliesTo(resType string) bool { return resType == "aws_sns_topic_policy" }

func (snsPolicyPublic) Check(r ir.Resource) []ir.Finding {
	rule := snsPolicyPublic{}
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyAllowsPublicPrincipal(doc) {
		return msgFinding(rule, r, "policy", span,
			"Allow statement with Principal \"*\"",
			"Principal scoped to specific AWS principals")
	}
	return nil
}

type sqsPolicyPublic struct{}

func (sqsPolicyPublic) ID() string    { return "AEGIS-AWS-344" }
func (sqsPolicyPublic) Title() string { return "SQS queue policy allows public principal" }
func (sqsPolicyPublic) Description() string {
	return "A queue policy Allow statement with Principal \"*\" grants " +
		"anonymous send/receive access to the queue."
}
func (sqsPolicyPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (sqsPolicyPublic) AppliesTo(resType string) bool { return resType == "aws_sqs_queue_policy" }

func (sqsPolicyPublic) Check(r ir.Resource) []ir.Finding {
	rule := sqsPolicyPublic{}
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyAllowsPublicPrincipal(doc) {
		return msgFinding(rule, r, "policy", span,
			"Allow statement with Principal \"*\"",
			"Principal scoped to specific AWS principals")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-345: MSK cluster without encryption
// ---------------------------------------------------------------------------

type mskNoEncryption struct{}

func (mskNoEncryption) ID() string    { return "AEGIS-AWS-345" }
func (mskNoEncryption) Title() string { return "MSK cluster without encryption" }
func (mskNoEncryption) Description() string {
	return "MSK clusters should encrypt data in transit. A cluster with no " +
		"encryption_info block, or with client_broker set to PLAINTEXT, " +
		"passes Kafka traffic unencrypted."
}
func (mskNoEncryption) Severity() ir.Severity { return ir.SeverityHigh }

func (mskNoEncryption) AppliesTo(resType string) bool { return resType == "aws_msk_cluster" }

func (mskNoEncryption) Check(r ir.Resource) []ir.Finding {
	rule := mskNoEncryption{}
	blks, span, present, known := getBlocks(r, "encryption_info")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(blks) == 0 {
		return msgFinding(rule, r, "encryption_info", span,
			"absent", "encryption_info block with client_broker set to TLS")
	}
	for _, b := range blks {
		cb, _, cpresent, cknown := blockString(b, "client_broker")
		if cpresent && !cknown {
			return nil // unresolved: cannot decide
		}
		if cpresent && strings.EqualFold(strings.TrimSpace(cb), "PLAINTEXT") {
			return msgFinding(rule, r, "encryption_info.client_broker", span,
				"PLAINTEXT", "client_broker set to TLS (or TLS_PLAINTEXT for migration only)")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-346: CloudWatch log group without KMS encryption
// ---------------------------------------------------------------------------

type cwLogGroupNoKMS struct{}

func (cwLogGroupNoKMS) ID() string    { return "AEGIS-AWS-346" }
func (cwLogGroupNoKMS) Title() string { return "CloudWatch log group without KMS encryption" }
func (cwLogGroupNoKMS) Description() string {
	return "CloudWatch log groups should encrypt log data at rest with a " +
		"KMS key. A group with no kms_key_id relies on the AWS-managed " +
		"default, which the account cannot control or rotate."
}
func (cwLogGroupNoKMS) Severity() ir.Severity { return ir.SeverityMedium }

func (cwLogGroupNoKMS) AppliesTo(resType string) bool { return resType == "aws_cloudwatch_log_group" }

func (cwLogGroupNoKMS) Check(r ir.Resource) []ir.Finding {
	rule := cwLogGroupNoKMS{}
	key, span, present, known := getString(r, "kms_key_id")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || strings.TrimSpace(key) == "" {
		return msgFinding(rule, r, "kms_key_id", span,
			"absent", "kms_key_id set to a KMS key ARN")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-347: CloudWatch log group without retention
// ---------------------------------------------------------------------------

type cwLogGroupNoRetain struct{}

func (cwLogGroupNoRetain) ID() string    { return "AEGIS-AWS-347" }
func (cwLogGroupNoRetain) Title() string { return "CloudWatch log group without retention" }
func (cwLogGroupNoRetain) Description() string {
	return "CloudWatch log groups should set retention_in_days so logs " +
		"expire on schedule. A group with no retention keeps logs forever, " +
		"growing cost and breach blast radius."
}
func (cwLogGroupNoRetain) Severity() ir.Severity { return ir.SeverityMedium }

func (cwLogGroupNoRetain) AppliesTo(resType string) bool {
	return resType == "aws_cloudwatch_log_group"
}

func (cwLogGroupNoRetain) Check(r ir.Resource) []ir.Finding {
	rule := cwLogGroupNoRetain{}
	days, span, present, known := getNumber(r, "retention_in_days")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || days == 0 {
		return msgFinding(rule, r, "retention_in_days", span,
			"absent or 0 (logs never expire)", "retention_in_days set (e.g. 90)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-348: GuardDuty detector disabled
// ---------------------------------------------------------------------------

type guardDutyDisabled struct{}

func (guardDutyDisabled) ID() string    { return "AEGIS-AWS-348" }
func (guardDutyDisabled) Title() string { return "GuardDuty detector disabled" }
func (guardDutyDisabled) Description() string {
	return "GuardDuty is the account's threat-detection baseline. A detector " +
		"with enable = false leaves the account without anomaly detection."
}
func (guardDutyDisabled) Severity() ir.Severity { return ir.SeverityMedium }

func (guardDutyDisabled) AppliesTo(resType string) bool { return resType == "aws_guardduty_detector" }

func (guardDutyDisabled) Check(r ir.Resource) []ir.Finding {
	rule := guardDutyDisabled{}
	en, span, present, known := getBool(r, "enable")
	if !present || !known {
		return nil // absent (provider default true) or unresolved: cannot decide
	}
	if !en {
		return msgFinding(rule, r, "enable", span,
			"false", "enable = true")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-349: MQ broker without encryption
// ---------------------------------------------------------------------------

type mqBrokerNoCMK struct{}

func (mqBrokerNoCMK) ID() string    { return "AEGIS-AWS-349" }
func (mqBrokerNoCMK) Title() string { return "MQ broker without customer-managed encryption" }
func (mqBrokerNoCMK) Description() string {
	return "Amazon MQ brokers should encrypt data at rest with a " +
		"customer-managed KMS key. A broker with no encryption_options block, " +
		"or with use_aws_owned_key = true, uses the AWS-owned key, which " +
		"cannot be audited, rotated, or revoked by the account."
}
func (mqBrokerNoCMK) Severity() ir.Severity { return ir.SeverityMedium }

func (mqBrokerNoCMK) AppliesTo(resType string) bool { return resType == "aws_mq_broker" }

func (mqBrokerNoCMK) Check(r ir.Resource) []ir.Finding {
	rule := mqBrokerNoCMK{}
	blks, span, present, known := getBlocks(r, "encryption_options")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(blks) == 0 {
		return msgFinding(rule, r, "encryption_options", span,
			"absent", "encryption_options block with use_aws_owned_key = false and a kms_key_id")
	}
	for _, b := range blks {
		awsOwned, _, opresent, oknown := blockBool(b, "use_aws_owned_key")
		if opresent && !oknown {
			return nil // unresolved: cannot decide
		}
		if opresent && awsOwned {
			return msgFinding(rule, r, "encryption_options.use_aws_owned_key", span,
				"true (AWS-owned key)", "use_aws_owned_key = false with a customer-managed kms_key_id")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-350: Kinesis stream without encryption
// ---------------------------------------------------------------------------

type kinesisNoEncryption struct{}

func (kinesisNoEncryption) ID() string    { return "AEGIS-AWS-350" }
func (kinesisNoEncryption) Title() string { return "Kinesis stream without encryption" }
func (kinesisNoEncryption) Description() string {
	return "Kinesis streams should encrypt records at rest. A stream with " +
		"no encryption_type (provider default NONE) stores records unencrypted."
}
func (kinesisNoEncryption) Severity() ir.Severity { return ir.SeverityHigh }

func (kinesisNoEncryption) AppliesTo(resType string) bool { return resType == "aws_kinesis_stream" }

func (kinesisNoEncryption) Check(r ir.Resource) []ir.Finding {
	rule := kinesisNoEncryption{}
	enc, span, present, known := getString(r, "encryption_type")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || strings.EqualFold(strings.TrimSpace(enc), "NONE") || strings.TrimSpace(enc) == "" {
		return msgFinding(rule, r, "encryption_type", span,
			"absent or NONE", "encryption_type = \"KMS\" with a kms_key_id")
	}
	return nil
}
