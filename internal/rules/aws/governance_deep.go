package aws

import (
	"encoding/json"
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// Deep governance & logging rules, AEGIS-AWS-760 through AEGIS-AWS-779.
//
// Unknown-value contract: a present-but-unresolved attribute yields no
// finding. An absent attribute is judged against the provider's documented
// insecure default via absentInsecureDefault.

// ---------------------------------------------------------------------------
// AEGIS-AWS-760: CloudTrail trail is not an organization trail
// ---------------------------------------------------------------------------

type cloudtrailOrgTrail struct{}

func (cloudtrailOrgTrail) ID() string { return "AEGIS-AWS-760" }
func (cloudtrailOrgTrail) Title() string {
	return "CloudTrail trail is not an organization trail"
}
func (cloudtrailOrgTrail) Description() string {
	return "A trail that is not an organization trail records API activity " +
		"for a single account only. An organization trail centralizes audit " +
		"logging across every account in the organization."
}
func (cloudtrailOrgTrail) Severity() ir.Severity { return ir.SeverityLow }

func (cloudtrailOrgTrail) AppliesTo(resType string) bool {
	return resType == "aws_cloudtrail"
}

func (cloudtrailOrgTrail) Check(r ir.Resource) []ir.Finding {
	rule := cloudtrailOrgTrail{}
	org, span, present, known := getBool(r, "is_organization_trail")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && org {
		return nil
	}
	if !present {
		return absentInsecureDefault(rule, r, "is_organization_trail",
			"absent (provider default: false)", "true")
	}
	return msgFinding(rule, r, "is_organization_trail", span, "false", "true")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-761: CloudTrail trail without CloudTrail Insights
// ---------------------------------------------------------------------------

type cloudtrailNoInsights struct{}

func (cloudtrailNoInsights) ID() string { return "AEGIS-AWS-761" }
func (cloudtrailNoInsights) Title() string {
	return "CloudTrail trail without CloudTrail Insights"
}
func (cloudtrailNoInsights) Description() string {
	return "CloudTrail Insights detects unusual API activity and errors " +
		"automatically. A trail with no insight_selector block never " +
		"benefits from anomaly detection on management events."
}
func (cloudtrailNoInsights) Severity() ir.Severity { return ir.SeverityLow }

func (cloudtrailNoInsights) AppliesTo(resType string) bool {
	return resType == "aws_cloudtrail"
}

func (cloudtrailNoInsights) Check(r ir.Resource) []ir.Finding {
	rule := cloudtrailNoInsights{}
	_, _, present, known := getBlocks(r, "insight_selector")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		return nil
	}
	return absentInsecureDefault(rule, r, "insight_selector",
		"absent (Insights not enabled)", "insight_selector block configured")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-762: CloudTrail trail logging disabled
// ---------------------------------------------------------------------------

type cloudtrailLoggingDisabled struct{}

func (cloudtrailLoggingDisabled) ID() string { return "AEGIS-AWS-762" }
func (cloudtrailLoggingDisabled) Title() string {
	return "CloudTrail trail logging disabled"
}
func (cloudtrailLoggingDisabled) Description() string {
	return "A CloudTrail trail with enable_logging = false exists but " +
		"records nothing, leaving API activity unaudited while looking " +
		"configured. (KMS coverage is AEGIS-AWS-568.)"
}
func (cloudtrailLoggingDisabled) Severity() ir.Severity { return ir.SeverityHigh }

func (cloudtrailLoggingDisabled) AppliesTo(resType string) bool {
	return resType == "aws_cloudtrail"
}

func (cloudtrailLoggingDisabled) Check(r ir.Resource) []ir.Finding {
	rule := cloudtrailLoggingDisabled{}
	en, span, present, known := getBool(r, "enable_logging")
	if !present || !known {
		return nil // provider default is true; unresolved: cannot decide
	}
	if en {
		return nil
	}
	return msgFinding(rule, r, "enable_logging", span, "false", "true")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-763: Config recorder skips global resource types
// ---------------------------------------------------------------------------

type configRecorderNoGlobalResources struct{}

func (configRecorderNoGlobalResources) ID() string { return "AEGIS-AWS-763" }
func (configRecorderNoGlobalResources) Title() string {
	return "Config recorder skips global resource types"
}
func (configRecorderNoGlobalResources) Description() string {
	return "A configuration recorder with include_global_resource_types = " +
		"false never records IAM, and other global services, leaving " +
		"identity-plane drift invisible to Config. (all_supported coverage " +
		"is AEGIS-AWS-393.)"
}
func (configRecorderNoGlobalResources) Severity() ir.Severity { return ir.SeverityMedium }

func (configRecorderNoGlobalResources) AppliesTo(resType string) bool {
	return resType == "aws_config_configuration_recorder"
}

func (configRecorderNoGlobalResources) Check(r ir.Resource) []ir.Finding {
	rule := configRecorderNoGlobalResources{}
	blks, span, present, known := getBlocks(r, "recording_group")
	if !present || !known {
		return nil // absent block records global types by default
	}
	for _, b := range blks {
		v, ok := b["include_global_resource_types"]
		if !ok || !v.Known {
			continue // unresolved: cannot decide
		}
		if inc, kok := v.AsBool(); kok && !inc {
			return msgFinding(rule, r, "recording_group.include_global_resource_types",
				evidenceSpan(v.Span, span), "false", "true")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-764: Config delivery channel without S3 key prefix
// ---------------------------------------------------------------------------

type configDeliveryNoKeyPrefix struct{}

func (configDeliveryNoKeyPrefix) ID() string { return "AEGIS-AWS-764" }
func (configDeliveryNoKeyPrefix) Title() string {
	return "Config delivery channel without S3 key prefix"
}
func (configDeliveryNoKeyPrefix) Description() string {
	return "A Config delivery channel with no s3_key_prefix writes " +
		"snapshots and history to the bucket root, mixing Config data " +
		"with anything else in the bucket and complicating lifecycle " +
		"and access scoping."
}
func (configDeliveryNoKeyPrefix) Severity() ir.Severity { return ir.SeverityLow }

func (configDeliveryNoKeyPrefix) AppliesTo(resType string) bool {
	return resType == "aws_config_delivery_channel"
}

func (configDeliveryNoKeyPrefix) Check(r ir.Resource) []ir.Finding {
	rule := configDeliveryNoKeyPrefix{}
	prefix, span, present, known := getString(r, "s3_key_prefix")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(prefix) != "" {
		return nil
	}
	actual := "absent"
	if present {
		actual = "empty"
	}
	return msgFinding(rule, r, "s3_key_prefix", span, actual, "dedicated prefix (e.g. \"config/\")")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-765: Config recorder status disabled
// ---------------------------------------------------------------------------

type configRecorderStatusDisabled struct{}

func (configRecorderStatusDisabled) ID() string { return "AEGIS-AWS-765" }
func (configRecorderStatusDisabled) Title() string {
	return "Config recorder status disabled"
}
func (configRecorderStatusDisabled) Description() string {
	return "An aws_config_configuration_recorder_status with is_enabled = " +
		"false stops the recorder: the recorder exists but captures no " +
		"configuration changes."
}
func (configRecorderStatusDisabled) Severity() ir.Severity { return ir.SeverityHigh }

func (configRecorderStatusDisabled) AppliesTo(resType string) bool {
	return resType == "aws_config_configuration_recorder_status"
}

func (configRecorderStatusDisabled) Check(r ir.Resource) []ir.Finding {
	rule := configRecorderStatusDisabled{}
	en, span, present, known := getBool(r, "is_enabled")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if en {
		return nil
	}
	return msgFinding(rule, r, "is_enabled", span, "false", "true")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-766: GuardDuty finding publishing disabled
// ---------------------------------------------------------------------------

type guarddutyFindingDisabled struct{}

func (guarddutyFindingDisabled) ID() string { return "AEGIS-AWS-766" }
func (guarddutyFindingDisabled) Title() string {
	return "GuardDuty finding publishing disabled"
}
func (guarddutyFindingDisabled) Description() string {
	return "A GuardDuty detector with finding_enabled = false suppresses " +
		"finding publication, so detections never reach EventBridge, " +
		"Security Hub, or the console. (Detector enable coverage is " +
		"AEGIS-AWS-348.)"
}
func (guarddutyFindingDisabled) Severity() ir.Severity { return ir.SeverityHigh }

func (guarddutyFindingDisabled) AppliesTo(resType string) bool {
	return resType == "aws_guardduty_detector"
}

func (guarddutyFindingDisabled) Check(r ir.Resource) []ir.Finding {
	rule := guarddutyFindingDisabled{}
	fe, span, present, known := getBool(r, "finding_enabled")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	if fe {
		return nil
	}
	return msgFinding(rule, r, "finding_enabled", span, "false", "true")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-767: GuardDuty S3 protection disabled
// ---------------------------------------------------------------------------

type guarddutyS3LogsDisabled struct{}

func (guarddutyS3LogsDisabled) ID() string { return "AEGIS-AWS-767" }
func (guarddutyS3LogsDisabled) Title() string {
	return "GuardDuty S3 protection disabled"
}
func (guarddutyS3LogsDisabled) Description() string {
	return "A GuardDuty detector with datasources.s3_logs.enable = false " +
		"stops monitoring S3 data-plane events, missing anomalous access " +
		"to buckets. Only an explicit opt-out is flagged; the provider " +
		"default keeps S3 protection on."
}
func (guarddutyS3LogsDisabled) Severity() ir.Severity { return ir.SeverityLow }

func (guarddutyS3LogsDisabled) AppliesTo(resType string) bool {
	return resType == "aws_guardduty_detector"
}

func (guarddutyS3LogsDisabled) Check(r ir.Resource) []ir.Finding {
	rule := guarddutyS3LogsDisabled{}
	dsBlks, _, present, known := getBlocks(r, "datasources")
	if !present || !known {
		return nil // absent: provider default keeps S3 protection enabled
	}
	for _, b := range dsBlks {
		for _, s3 := range blockList(b, "s3_logs") {
			en, espan, epresent, eknown := blockBool(s3, "enable")
			if !epresent || !eknown {
				continue // unresolved: cannot decide
			}
			if !en {
				return msgFinding(rule, r, "datasources.s3_logs.enable",
					espan, "false", "true")
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-768: Macie finding publishing slower than 15 minutes
// ---------------------------------------------------------------------------

type macieSlowPublishing struct{}

func (macieSlowPublishing) ID() string { return "AEGIS-AWS-768" }
func (macieSlowPublishing) Title() string {
	return "Macie finding publishing slower than 15 minutes"
}
func (macieSlowPublishing) Description() string {
	return "A Macie account whose finding_publishing_frequency is not " +
		"FIFTEEN_MINUTES delays sensitive-data findings by up to six " +
		"hours, slowing incident response."
}
func (macieSlowPublishing) Severity() ir.Severity { return ir.SeverityLow }

func (macieSlowPublishing) AppliesTo(resType string) bool {
	return resType == "aws_macie2_account"
}

func (macieSlowPublishing) Check(r ir.Resource) []ir.Finding {
	rule := macieSlowPublishing{}
	freq, span, present, known := getString(r, "finding_publishing_frequency")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return absentInsecureDefault(rule, r, "finding_publishing_frequency",
			"absent (provider default: SIX_HOURS)", "FIFTEEN_MINUTES")
	}
	if strings.TrimSpace(freq) != "FIFTEEN_MINUTES" {
		return msgFinding(rule, r, "finding_publishing_frequency", span,
			freq, "FIFTEEN_MINUTES")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-769: CloudWatch log group with short retention
// ---------------------------------------------------------------------------

type cwLogGroupShortRetention struct{}

func (cwLogGroupShortRetention) ID() string { return "AEGIS-AWS-769" }
func (cwLogGroupShortRetention) Title() string {
	return "CloudWatch log group with short log retention"
}
func (cwLogGroupShortRetention) Description() string {
	return "A log group with retention_in_days below 30 days shrinks the " +
		"forensic window: incidents discovered late have no logs to " +
		"investigate. (Absent or never-expire retention is AEGIS-AWS-347.)"
}
func (cwLogGroupShortRetention) Severity() ir.Severity { return ir.SeverityLow }

func (cwLogGroupShortRetention) AppliesTo(resType string) bool {
	return resType == "aws_cloudwatch_log_group"
}

func (cwLogGroupShortRetention) Check(r ir.Resource) []ir.Finding {
	rule := cwLogGroupShortRetention{}
	days, span, present, known := getNumber(r, "retention_in_days")
	if !present || !known {
		return nil // AEGIS-AWS-347 covers absent; unresolved: cannot decide
	}
	if days == 0 || days >= 30 {
		return nil
	}
	return msgFinding(rule, r, "retention_in_days", span,
		fmt.Sprintf("%.0f days", days), ">= 30 days")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-770: CloudWatch log group using AWS-managed encryption key
// ---------------------------------------------------------------------------

type cwLogGroupAWSManagedKey struct{}

func (cwLogGroupAWSManagedKey) ID() string { return "AEGIS-AWS-770" }
func (cwLogGroupAWSManagedKey) Title() string {
	return "CloudWatch log group using AWS-managed encryption key"
}
func (cwLogGroupAWSManagedKey) Description() string {
	return "A log group with kms_key_id explicitly set to alias/aws/logs " +
		"encrypts with the AWS-managed key, which the account cannot " +
		"rotate or control via key policy. Use a customer-managed key. " +
		"(Missing kms_key_id is AEGIS-AWS-346.)"
}
func (cwLogGroupAWSManagedKey) Severity() ir.Severity { return ir.SeverityMedium }

func (cwLogGroupAWSManagedKey) AppliesTo(resType string) bool {
	return resType == "aws_cloudwatch_log_group"
}

func (cwLogGroupAWSManagedKey) Check(r ir.Resource) []ir.Finding {
	rule := cwLogGroupAWSManagedKey{}
	key, span, present, known := getString(r, "kms_key_id")
	if !present || !known {
		return nil // AEGIS-AWS-346 covers absent; unresolved: cannot decide
	}
	if isAWSManagedKeyAlias(strings.TrimSpace(key), "alias/aws/logs") {
		return msgFinding(rule, r, "kms_key_id", span,
			strings.TrimSpace(key), "customer-managed KMS key")
	}
	return nil
}

// isAWSManagedKeyAlias reports whether a kms key reference is the given
// AWS-managed alias, either bare ("alias/aws/logs") or as a full ARN.
func isAWSManagedKeyAlias(key, alias string) bool {
	if key == alias {
		return true
	}
	return strings.HasSuffix(key, ":"+alias)
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-771: CloudWatch alarm with no alarm actions
// ---------------------------------------------------------------------------

type cwAlarmNoActions struct{}

func (cwAlarmNoActions) ID() string { return "AEGIS-AWS-771" }
func (cwAlarmNoActions) Title() string {
	return "CloudWatch alarm with no alarm actions"
}
func (cwAlarmNoActions) Description() string {
	return "A metric alarm with no alarm_actions transitions silently: " +
		"nobody is paged or notified when the threshold breaches, so the " +
		"alarm is monitoring theater."
}
func (cwAlarmNoActions) Severity() ir.Severity { return ir.SeverityLow }

func (cwAlarmNoActions) AppliesTo(resType string) bool {
	return resType == "aws_cloudwatch_metric_alarm"
}

func (cwAlarmNoActions) Check(r ir.Resource) []ir.Finding {
	rule := cwAlarmNoActions{}
	v, ok := r.Attributes["alarm_actions"]
	if !ok {
		return msgFinding(rule, r, "alarm_actions", r.Span,
			"absent", "alarm_actions with at least one SNS topic or ARN")
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	l, ok := v.AsList()
	if !ok {
		return nil // unexpected shape: cannot decide
	}
	if len(l) == 0 {
		return msgFinding(rule, r, "alarm_actions", evidenceSpan(v.Span, r.Span),
			"empty", "alarm_actions with at least one SNS topic or ARN")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-772: SNS topic using AWS-managed encryption key
// ---------------------------------------------------------------------------

type snsTopicAWSManagedKey struct{}

func (snsTopicAWSManagedKey) ID() string { return "AEGIS-AWS-772" }
func (snsTopicAWSManagedKey) Title() string {
	return "SNS topic using AWS-managed encryption key"
}
func (snsTopicAWSManagedKey) Description() string {
	return "A topic with kms_master_key_id explicitly set to " +
		"alias/aws/sns encrypts with the AWS-managed key, which the " +
		"account cannot rotate or control via key policy. Use a " +
		"customer-managed key. (Missing kms_master_key_id is AEGIS-AWS-341.)"
}
func (snsTopicAWSManagedKey) Severity() ir.Severity { return ir.SeverityMedium }

func (snsTopicAWSManagedKey) AppliesTo(resType string) bool {
	return resType == "aws_sns_topic"
}

func (snsTopicAWSManagedKey) Check(r ir.Resource) []ir.Finding {
	rule := snsTopicAWSManagedKey{}
	key, span, present, known := getString(r, "kms_master_key_id")
	if !present || !known {
		return nil // AEGIS-AWS-341 covers absent; unresolved: cannot decide
	}
	if isAWSManagedKeyAlias(strings.TrimSpace(key), "alias/aws/sns") {
		return msgFinding(rule, r, "kms_master_key_id", span,
			strings.TrimSpace(key), "customer-managed KMS key")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-773: SNS topic without display name
// ---------------------------------------------------------------------------

type snsTopicNoDisplayName struct{}

func (snsTopicNoDisplayName) ID() string { return "AEGIS-AWS-773" }
func (snsTopicNoDisplayName) Title() string {
	return "SNS topic without display name"
}
func (snsTopicNoDisplayName) Description() string {
	return "A topic with no display_name is harder to identify in " +
		"notifications and audit trails. Set a human-readable display " +
		"name for every topic."
}
func (snsTopicNoDisplayName) Severity() ir.Severity { return ir.SeverityLow }

func (snsTopicNoDisplayName) AppliesTo(resType string) bool {
	return resType == "aws_sns_topic"
}

func (snsTopicNoDisplayName) Check(r ir.Resource) []ir.Finding {
	rule := snsTopicNoDisplayName{}
	name, span, present, known := getString(r, "display_name")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(name) != "" {
		return nil
	}
	actual := "absent"
	if present {
		actual = "empty"
	}
	return msgFinding(rule, r, "display_name", span, actual, "human-readable display name")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-774: SNS topic policy grants wildcard actions
// ---------------------------------------------------------------------------

type snsTopicPolicyWildcardActions struct{}

func (snsTopicPolicyWildcardActions) ID() string { return "AEGIS-AWS-774" }
func (snsTopicPolicyWildcardActions) Title() string {
	return "SNS topic policy grants wildcard actions"
}
func (snsTopicPolicyWildcardActions) Description() string {
	return "A topic policy Allow statement that grants \"*\" or \"sns:*\" " +
		"to a named principal is overprivileged: publish, subscribe, and " +
		"topic administration collapse into one grant. (Public-principal " +
		"statements are AEGIS-AWS-343.)"
}
func (snsTopicPolicyWildcardActions) Severity() ir.Severity { return ir.SeverityMedium }

func (snsTopicPolicyWildcardActions) AppliesTo(resType string) bool {
	return resType == "aws_sns_topic_policy"
}

func (snsTopicPolicyWildcardActions) Check(r ir.Resource) []ir.Finding {
	rule := snsTopicPolicyWildcardActions{}
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyAllowWildcardActions(doc) {
		return msgFinding(rule, r, "policy", span,
			"Allow statement with wildcard action", "least-privilege sns: actions")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-775: SQS queue using AWS-managed encryption key
// ---------------------------------------------------------------------------

type sqsQueueAWSManagedKey struct{}

func (sqsQueueAWSManagedKey) ID() string { return "AEGIS-AWS-775" }
func (sqsQueueAWSManagedKey) Title() string {
	return "SQS queue using AWS-managed encryption key"
}
func (sqsQueueAWSManagedKey) Description() string {
	return "A queue with kms_master_key_id explicitly set to " +
		"alias/aws/sqs encrypts with the AWS-managed key, which the " +
		"account cannot rotate or control via key policy. Use a " +
		"customer-managed key. (No encryption at all is AEGIS-AWS-342.)"
}
func (sqsQueueAWSManagedKey) Severity() ir.Severity { return ir.SeverityMedium }

func (sqsQueueAWSManagedKey) AppliesTo(resType string) bool {
	return resType == "aws_sqs_queue"
}

func (sqsQueueAWSManagedKey) Check(r ir.Resource) []ir.Finding {
	rule := sqsQueueAWSManagedKey{}
	key, span, present, known := getString(r, "kms_master_key_id")
	if !present || !known {
		return nil // AEGIS-AWS-342 covers the unencrypted case; unresolved: cannot decide
	}
	if isAWSManagedKeyAlias(strings.TrimSpace(key), "alias/aws/sqs") {
		return msgFinding(rule, r, "kms_master_key_id", span,
			strings.TrimSpace(key), "customer-managed KMS key")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-776: SQS queue with zero visibility timeout
// ---------------------------------------------------------------------------

type sqsQueueZeroVisibilityTimeout struct{}

func (sqsQueueZeroVisibilityTimeout) ID() string { return "AEGIS-AWS-776" }
func (sqsQueueZeroVisibilityTimeout) Title() string {
	return "SQS queue with zero visibility timeout"
}
func (sqsQueueZeroVisibilityTimeout) Description() string {
	return "A queue with visibility_timeout_seconds = 0 makes a received " +
		"message immediately visible again, so concurrent consumers " +
		"process the same message and poison messages loop without " +
		"backoff."
}
func (sqsQueueZeroVisibilityTimeout) Severity() ir.Severity { return ir.SeverityLow }

func (sqsQueueZeroVisibilityTimeout) AppliesTo(resType string) bool {
	return resType == "aws_sqs_queue"
}

func (sqsQueueZeroVisibilityTimeout) Check(r ir.Resource) []ir.Finding {
	rule := sqsQueueZeroVisibilityTimeout{}
	to, span, present, known := getNumber(r, "visibility_timeout_seconds")
	if !present || !known {
		return nil // provider default is 30; unresolved: cannot decide
	}
	if to != 0 {
		return nil
	}
	return msgFinding(rule, r, "visibility_timeout_seconds", span,
		"0", "positive visibility timeout (e.g. 30)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-777: SQS queue with short message retention
// ---------------------------------------------------------------------------

type sqsQueueShortRetention struct{}

func (sqsQueueShortRetention) ID() string { return "AEGIS-AWS-777" }
func (sqsQueueShortRetention) Title() string {
	return "SQS queue with short message retention"
}
func (sqsQueueShortRetention) Description() string {
	return "A queue with message_retention_seconds below the 345600 " +
		"second (4 day) default drops undelivered messages early, losing " +
		"messages during extended consumer outages."
}
func (sqsQueueShortRetention) Severity() ir.Severity { return ir.SeverityLow }

func (sqsQueueShortRetention) AppliesTo(resType string) bool {
	return resType == "aws_sqs_queue"
}

func (sqsQueueShortRetention) Check(r ir.Resource) []ir.Finding {
	rule := sqsQueueShortRetention{}
	ret, span, present, known := getNumber(r, "message_retention_seconds")
	if !present || !known {
		return nil // provider default is 345600; unresolved: cannot decide
	}
	if ret >= 345600 {
		return nil
	}
	return msgFinding(rule, r, "message_retention_seconds", span,
		fmt.Sprintf("%.0f seconds", ret), ">= 345600 seconds (4 days)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-778: SQS queue policy grants wildcard actions
// ---------------------------------------------------------------------------

type sqsQueuePolicyWildcardActions struct{}

func (sqsQueuePolicyWildcardActions) ID() string { return "AEGIS-AWS-778" }
func (sqsQueuePolicyWildcardActions) Title() string {
	return "SQS queue policy grants wildcard actions"
}
func (sqsQueuePolicyWildcardActions) Description() string {
	return "A queue policy Allow statement that grants \"*\" or \"sqs:*\" " +
		"to a named principal is overprivileged: send, receive, and queue " +
		"administration collapse into one grant. (Public-principal " +
		"statements are AEGIS-AWS-344.)"
}
func (sqsQueuePolicyWildcardActions) Severity() ir.Severity { return ir.SeverityMedium }

func (sqsQueuePolicyWildcardActions) AppliesTo(resType string) bool {
	return resType == "aws_sqs_queue_policy"
}

func (sqsQueuePolicyWildcardActions) Check(r ir.Resource) []ir.Finding {
	rule := sqsQueuePolicyWildcardActions{}
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyAllowWildcardActions(doc) {
		return msgFinding(rule, r, "policy", span,
			"Allow statement with wildcard action", "least-privilege sqs: actions")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-779: SNS subscription without dead-letter queue
// ---------------------------------------------------------------------------

type snsSubscriptionNoDLQ struct{}

func (snsSubscriptionNoDLQ) ID() string { return "AEGIS-AWS-779" }
func (snsSubscriptionNoDLQ) Title() string {
	return "SNS subscription without dead-letter queue"
}
func (snsSubscriptionNoDLQ) Description() string {
	return "A subscription with no redrive_policy block drops messages " +
		"that exhaust delivery retries, silently losing notifications " +
		"during endpoint outages. (Plaintext HTTP delivery is " +
		"AEGIS-AWS-426.)"
}
func (snsSubscriptionNoDLQ) Severity() ir.Severity { return ir.SeverityLow }

func (snsSubscriptionNoDLQ) AppliesTo(resType string) bool {
	return resType == "aws_sns_topic_subscription"
}

func (snsSubscriptionNoDLQ) Check(r ir.Resource) []ir.Finding {
	rule := snsSubscriptionNoDLQ{}
	_, _, present, known := getBlocks(r, "redrive_policy")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		return nil
	}
	return absentInsecureDefault(rule, r, "redrive_policy",
		"absent (failed deliveries are dropped)", "redrive_policy with deadLetterTargetArn")
}

// policyAllowWildcardActions reports whether any Allow statement with a
// non-public principal grants a wildcard action ("*" or "<service>:*").
// Statements with a public principal are skipped: those are covered by the
// dedicated public-principal rules. Malformed JSON yields false.
func policyAllowWildcardActions(doc string) bool {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
	}
	if len(parsed.Statement) == 0 {
		return false
	}
	var stmts []map[string]any
	if parsed.Statement[0] == '[' {
		if err := json.Unmarshal(parsed.Statement, &stmts); err != nil {
			return false
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(parsed.Statement, &one); err != nil {
			return false
		}
		stmts = []map[string]any{one}
	}
	for _, s := range stmts {
		eff, _ := s["Effect"].(string)
		if eff != "Allow" {
			continue
		}
		if s["Principal"] == nil || principalIsPublic(s["Principal"]) {
			continue
		}
		if actionsWildcard(s["Action"]) {
			return true
		}
	}
	return false
}

// actionsWildcard reports whether an Action value is "*" or ends in ":*".
func actionsWildcard(a any) bool {
	switch v := a.(type) {
	case string:
		t := strings.TrimSpace(v)
		return t == "*" || strings.HasSuffix(t, ":*")
	case []any:
		for _, item := range v {
			if actionsWildcard(item) {
				return true
			}
		}
	}
	return false
}

// GovernanceDeepRules returns the deep governance & logging rules, in ID order.
func GovernanceDeepRules() []ir.Rule {
	return []ir.Rule{
		cloudtrailOrgTrail{},              // AEGIS-AWS-760
		cloudtrailNoInsights{},            // AEGIS-AWS-761
		cloudtrailLoggingDisabled{},       // AEGIS-AWS-762
		configRecorderNoGlobalResources{}, // AEGIS-AWS-763
		configDeliveryNoKeyPrefix{},       // AEGIS-AWS-764
		configRecorderStatusDisabled{},    // AEGIS-AWS-765
		guarddutyFindingDisabled{},        // AEGIS-AWS-766
		guarddutyS3LogsDisabled{},         // AEGIS-AWS-767
		macieSlowPublishing{},             // AEGIS-AWS-768
		cwLogGroupShortRetention{},        // AEGIS-AWS-769
		cwLogGroupAWSManagedKey{},         // AEGIS-AWS-770
		cwAlarmNoActions{},                // AEGIS-AWS-771
		snsTopicAWSManagedKey{},           // AEGIS-AWS-772
		snsTopicNoDisplayName{},           // AEGIS-AWS-773
		snsTopicPolicyWildcardActions{},   // AEGIS-AWS-774
		sqsQueueAWSManagedKey{},           // AEGIS-AWS-775
		sqsQueueZeroVisibilityTimeout{},   // AEGIS-AWS-776
		sqsQueueShortRetention{},          // AEGIS-AWS-777
		sqsQueuePolicyWildcardActions{},   // AEGIS-AWS-778
		snsSubscriptionNoDLQ{},            // AEGIS-AWS-779
	}
}
