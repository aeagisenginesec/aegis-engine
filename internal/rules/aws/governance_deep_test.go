package aws

import (
	"testing"

	"aegis/internal/ir"
)

func Test760_AbsentFires(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{})
	fs := runRule(cloudtrailOrgTrail{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test760_TrueQuiet(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{"is_organization_trail": kv(true, 3)})
	if fs := runRule(cloudtrailOrgTrail{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test760_UnknownQuiet(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{"is_organization_trail": ku(3)})
	if fs := runRule(cloudtrailOrgTrail{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test761_AbsentFires(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{})
	fs := runRule(cloudtrailNoInsights{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test761_PresentQuiet(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{
		"insight_selector": blks(4, blk("insight_type", ks("ApiCallRateInsight", 5))),
	})
	if fs := runRule(cloudtrailNoInsights{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test762_LoggingDisabledFires(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{"enable_logging": kv(false, 3)})
	fs := runRule(cloudtrailLoggingDisabled{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test762_LoggingEnabledQuiet(t *testing.T) {
	r := res("aws_cloudtrail", "t", map[string]ir.Value{"enable_logging": kv(true, 3)})
	if fs := runRule(cloudtrailLoggingDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test763_NoGlobalResourcesFires(t *testing.T) {
	r := res("aws_config_configuration_recorder", "r", map[string]ir.Value{
		"recording_group": blks(4, blk("include_global_resource_types", kv(false, 5))),
	})
	fs := runRule(configRecorderNoGlobalResources{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test763_GlobalResourcesQuiet(t *testing.T) {
	r := res("aws_config_configuration_recorder", "r", map[string]ir.Value{
		"recording_group": blks(4, blk("include_global_resource_types", kv(true, 5))),
	})
	if fs := runRule(configRecorderNoGlobalResources{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test764_AbsentFires(t *testing.T) {
	r := res("aws_config_delivery_channel", "c", map[string]ir.Value{})
	fs := runRule(configDeliveryNoKeyPrefix{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test764_WithPrefixQuiet(t *testing.T) {
	r := res("aws_config_delivery_channel", "c", map[string]ir.Value{"s3_key_prefix": ks("config/", 3)})
	if fs := runRule(configDeliveryNoKeyPrefix{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test764_UnknownQuiet(t *testing.T) {
	r := res("aws_config_delivery_channel", "c", map[string]ir.Value{"s3_key_prefix": ku(3)})
	if fs := runRule(configDeliveryNoKeyPrefix{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test765_DisabledFires(t *testing.T) {
	r := res("aws_config_configuration_recorder_status", "s", map[string]ir.Value{"is_enabled": kv(false, 3)})
	fs := runRule(configRecorderStatusDisabled{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test765_EnabledQuiet(t *testing.T) {
	r := res("aws_config_configuration_recorder_status", "s", map[string]ir.Value{"is_enabled": kv(true, 3)})
	if fs := runRule(configRecorderStatusDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test766_FindingDisabledFires(t *testing.T) {
	r := res("aws_guardduty_detector", "d", map[string]ir.Value{"finding_enabled": kv(false, 3)})
	fs := runRule(guarddutyFindingDisabled{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test766_AbsentQuiet(t *testing.T) {
	r := res("aws_guardduty_detector", "d", map[string]ir.Value{})
	if fs := runRule(guarddutyFindingDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test767_S3LogsDisabledFires(t *testing.T) {
	r := res("aws_guardduty_detector", "d", map[string]ir.Value{
		"datasources": blks(4, blk("s3_logs", blks(5, blk("enable", kv(false, 6))))),
	})
	fs := runRule(guarddutyS3LogsDisabled{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test767_S3LogsEnabledQuiet(t *testing.T) {
	r := res("aws_guardduty_detector", "d", map[string]ir.Value{
		"datasources": blks(4, blk("s3_logs", blks(5, blk("enable", kv(true, 6))))),
	})
	if fs := runRule(guarddutyS3LogsDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test767_NoDatasourcesQuiet(t *testing.T) {
	r := res("aws_guardduty_detector", "d", map[string]ir.Value{})
	if fs := runRule(guarddutyS3LogsDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test768_AbsentFires(t *testing.T) {
	r := res("aws_macie2_account", "m", map[string]ir.Value{})
	fs := runRule(macieSlowPublishing{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test768_FifteenMinutesQuiet(t *testing.T) {
	r := res("aws_macie2_account", "m", map[string]ir.Value{"finding_publishing_frequency": ks("FIFTEEN_MINUTES", 3)})
	if fs := runRule(macieSlowPublishing{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test768_SixHoursFires(t *testing.T) {
	r := res("aws_macie2_account", "m", map[string]ir.Value{"finding_publishing_frequency": ks("SIX_HOURS", 3)})
	fs := runRule(macieSlowPublishing{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test769_ShortRetentionFires(t *testing.T) {
	r := res("aws_cloudwatch_log_group", "g", map[string]ir.Value{"retention_in_days": kn(7, 3)})
	fs := runRule(cwLogGroupShortRetention{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test769_LongRetentionQuiet(t *testing.T) {
	r := res("aws_cloudwatch_log_group", "g", map[string]ir.Value{"retention_in_days": kn(90, 3)})
	if fs := runRule(cwLogGroupShortRetention{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test769_ZeroQuiet(t *testing.T) {
	// retention 0 (never expire) is AEGIS-AWS-347's case, not this rule's.
	r := res("aws_cloudwatch_log_group", "g", map[string]ir.Value{"retention_in_days": kn(0, 3)})
	if fs := runRule(cwLogGroupShortRetention{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test770_AWSManagedKeyFires(t *testing.T) {
	r := res("aws_cloudwatch_log_group", "g", map[string]ir.Value{"kms_key_id": ks("alias/aws/logs", 3)})
	fs := runRule(cwLogGroupAWSManagedKey{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test770_CMKQuiet(t *testing.T) {
	r := res("aws_cloudwatch_log_group", "g", map[string]ir.Value{"kms_key_id": ks("arn:aws:kms:us-east-1:123:key/abcd", 3)})
	if fs := runRule(cwLogGroupAWSManagedKey{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test770_AbsentQuiet(t *testing.T) {
	// absent kms_key_id is AEGIS-AWS-346's case.
	r := res("aws_cloudwatch_log_group", "g", map[string]ir.Value{})
	if fs := runRule(cwLogGroupAWSManagedKey{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test771_AbsentFires(t *testing.T) {
	r := res("aws_cloudwatch_metric_alarm", "a", map[string]ir.Value{})
	fs := runRule(cwAlarmNoActions{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test771_WithActionsQuiet(t *testing.T) {
	r := res("aws_cloudwatch_metric_alarm", "a", map[string]ir.Value{
		"alarm_actions": strList(3, "arn:aws:sns:us-east-1:123:alerts"),
	})
	if fs := runRule(cwAlarmNoActions{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test771_UnknownQuiet(t *testing.T) {
	r := res("aws_cloudwatch_metric_alarm", "a", map[string]ir.Value{"alarm_actions": ku(3)})
	if fs := runRule(cwAlarmNoActions{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test772_AWSManagedKeyFires(t *testing.T) {
	r := res("aws_sns_topic", "t", map[string]ir.Value{"kms_master_key_id": ks("alias/aws/sns", 3)})
	fs := runRule(snsTopicAWSManagedKey{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test772_CMKQuiet(t *testing.T) {
	r := res("aws_sns_topic", "t", map[string]ir.Value{"kms_master_key_id": ks("arn:aws:kms:us-east-1:123:key/abcd", 3)})
	if fs := runRule(snsTopicAWSManagedKey{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test773_AbsentFires(t *testing.T) {
	r := res("aws_sns_topic", "t", map[string]ir.Value{})
	fs := runRule(snsTopicNoDisplayName{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test773_WithNameQuiet(t *testing.T) {
	r := res("aws_sns_topic", "t", map[string]ir.Value{"display_name": ks("Alerts", 3)})
	if fs := runRule(snsTopicNoDisplayName{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test774_WildcardActionFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/app"},"Action":"sns:*"}]}`
	r := res("aws_sns_topic_policy", "p", map[string]ir.Value{"policy": ks(doc, 3)})
	fs := runRule(snsTopicPolicyWildcardActions{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test774_PublicPrincipalQuiet(t *testing.T) {
	// Public principals are AEGIS-AWS-343's case; this rule skips them.
	doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:*"}]}`
	r := res("aws_sns_topic_policy", "p", map[string]ir.Value{"policy": ks(doc, 3)})
	if fs := runRule(snsTopicPolicyWildcardActions{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test774_ScopedActionsQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/app"},"Action":["sns:Publish","sns:Subscribe"]}]}`
	r := res("aws_sns_topic_policy", "p", map[string]ir.Value{"policy": ks(doc, 3)})
	if fs := runRule(snsTopicPolicyWildcardActions{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test775_AWSManagedKeyFires(t *testing.T) {
	r := res("aws_sqs_queue", "q", map[string]ir.Value{"kms_master_key_id": ks("alias/aws/sqs", 3)})
	fs := runRule(sqsQueueAWSManagedKey{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test775_CMKQuiet(t *testing.T) {
	r := res("aws_sqs_queue", "q", map[string]ir.Value{"kms_master_key_id": ks("arn:aws:kms:us-east-1:123:key/abcd", 3)})
	if fs := runRule(sqsQueueAWSManagedKey{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test776_ZeroFires(t *testing.T) {
	r := res("aws_sqs_queue", "q", map[string]ir.Value{"visibility_timeout_seconds": kn(0, 3)})
	fs := runRule(sqsQueueZeroVisibilityTimeout{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test776_PositiveQuiet(t *testing.T) {
	r := res("aws_sqs_queue", "q", map[string]ir.Value{"visibility_timeout_seconds": kn(30, 3)})
	if fs := runRule(sqsQueueZeroVisibilityTimeout{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test776_AbsentQuiet(t *testing.T) {
	r := res("aws_sqs_queue", "q", map[string]ir.Value{})
	if fs := runRule(sqsQueueZeroVisibilityTimeout{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test777_ShortRetentionFires(t *testing.T) {
	r := res("aws_sqs_queue", "q", map[string]ir.Value{"message_retention_seconds": kn(3600, 3)})
	fs := runRule(sqsQueueShortRetention{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test777_DefaultQuiet(t *testing.T) {
	r := res("aws_sqs_queue", "q", map[string]ir.Value{"message_retention_seconds": kn(345600, 3)})
	if fs := runRule(sqsQueueShortRetention{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test778_WildcardActionFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/app"},"Action":["sqs:SendMessage","sqs:*"]}]}`
	r := res("aws_sqs_queue_policy", "p", map[string]ir.Value{"policy": ks(doc, 3)})
	fs := runRule(sqsQueuePolicyWildcardActions{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test778_ScopedActionsQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/app"},"Action":"sqs:SendMessage"}]}`
	r := res("aws_sqs_queue_policy", "p", map[string]ir.Value{"policy": ks(doc, 3)})
	if fs := runRule(sqsQueuePolicyWildcardActions{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test779_AbsentFires(t *testing.T) {
	r := res("aws_sns_topic_subscription", "s", map[string]ir.Value{"protocol": ks("https", 3)})
	fs := runRule(snsSubscriptionNoDLQ{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityLow {
		t.Fatalf("want low, got %s", fs[0].Severity)
	}
}

func Test779_WithDLQQuiet(t *testing.T) {
	r := res("aws_sns_topic_subscription", "s", map[string]ir.Value{
		"redrive_policy": blks(4, blk("deadLetterTargetArn", ks("arn:aws:sqs:us-east-1:123:dlq", 5))),
	})
	if fs := runRule(snsSubscriptionNoDLQ{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}
