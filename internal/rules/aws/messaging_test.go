package aws

import (
	"testing"

	"aegis/internal/ir"
)

// Messaging & monitoring rules (AEGIS-AWS-341..350): positive +
// compliant-negative + unknown-value test per rule.

// --- 341: SNS topic without KMS encryption ---

func Test341_AbsentFires(t *testing.T) {
	f := runRule(snsNoKMS{}, res("aws_sns_topic", "alerts", map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	if f[0].Severity != ir.SeverityHigh || f[0].Evidence.Attribute != "kms_master_key_id" {
		t.Fatalf("wrong finding: %+v", f[0])
	}
}

func Test341_KeySetQuiet(t *testing.T) {
	for _, key := range []string{"arn:aws:kms:us-east-1:123:key/abc", "alias/aws/sns"} {
		f := runRule(snsNoKMS{}, res("aws_sns_topic", "alerts",
			map[string]ir.Value{"kms_master_key_id": ks(key, 3)}))
		if len(f) != 0 {
			t.Fatalf("key=%q: got %d findings, want 0", key, len(f))
		}
	}
}

func Test341_UnknownQuiet(t *testing.T) {
	f := runRule(snsNoKMS{}, res("aws_sns_topic", "alerts",
		map[string]ir.Value{"kms_master_key_id": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 342: SQS queue without encryption ---

func Test342_ManagedSSEOffFires(t *testing.T) {
	f := runRule(sqsNoEncryption{}, res("aws_sqs_queue", "jobs",
		map[string]ir.Value{"sqs_managed_sse_enabled": kv(false, 4)}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test342_ManagedSSEOnQuiet(t *testing.T) {
	f := runRule(sqsNoEncryption{}, res("aws_sqs_queue", "jobs",
		map[string]ir.Value{"sqs_managed_sse_enabled": kv(true, 4)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test342_KMSKeyQuiet(t *testing.T) {
	// SSE-KMS silences the rule even with SSE-SQS off.
	f := runRule(sqsNoEncryption{}, res("aws_sqs_queue", "jobs",
		map[string]ir.Value{
			"sqs_managed_sse_enabled": kv(false, 4),
			"kms_master_key_id":       ks("arn:aws:kms:us-east-1:123:key/abc", 5),
		}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test342_UnknownQuiet(t *testing.T) {
	f := runRule(sqsNoEncryption{}, res("aws_sqs_queue", "jobs",
		map[string]ir.Value{"sqs_managed_sse_enabled": ku(4)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 343: SNS topic policy allows public principal ---

var publicTopicPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish","Resource":"*"}]}`
var awsStarTopicPolicy = `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sns:Subscribe"}}`
var scopedTopicPolicy = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"sns:Publish"}]}`

func Test343_StarPrincipalFires(t *testing.T) {
	for _, doc := range []string{publicTopicPolicy, awsStarTopicPolicy} {
		f := runRule(snsPolicyPublic{}, res("aws_sns_topic_policy", "p",
			map[string]ir.Value{"policy": ks(doc, 6)}))
		if len(f) != 1 {
			t.Fatalf("doc=%q: got %d findings, want 1", doc[:40], len(f))
		}
	}
}

func Test343_ScopedPrincipalQuiet(t *testing.T) {
	f := runRule(snsPolicyPublic{}, res("aws_sns_topic_policy", "p",
		map[string]ir.Value{"policy": ks(scopedTopicPolicy, 6)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test343_BadJSONQuiet(t *testing.T) {
	f := runRule(snsPolicyPublic{}, res("aws_sns_topic_policy", "p",
		map[string]ir.Value{"policy": ks("{not json", 6)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test343_UnknownQuiet(t *testing.T) {
	f := runRule(snsPolicyPublic{}, res("aws_sns_topic_policy", "p",
		map[string]ir.Value{"policy": ku(6)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 344: SQS queue policy allows public principal ---

func Test344_StarPrincipalFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage"}]}`
	f := runRule(sqsPolicyPublic{}, res("aws_sqs_queue_policy", "p",
		map[string]ir.Value{"policy": ks(doc, 6)}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test344_ScopedPrincipalQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sqs:*"}]}`
	f := runRule(sqsPolicyPublic{}, res("aws_sqs_queue_policy", "p",
		map[string]ir.Value{"policy": ks(doc, 6)}))
	if len(f) != 0 {
		t.Fatalf("Deny statement must not fire, got %d findings", len(f))
	}
}

func Test344_UnknownQuiet(t *testing.T) {
	f := runRule(sqsPolicyPublic{}, res("aws_sqs_queue_policy", "p",
		map[string]ir.Value{"policy": ku(6)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 345: MSK cluster without encryption ---

func Test345_AbsentBlockFires(t *testing.T) {
	f := runRule(mskNoEncryption{}, res("aws_msk_cluster", "kafka", map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test345_PlaintextFires(t *testing.T) {
	f := runRule(mskNoEncryption{}, res("aws_msk_cluster", "kafka",
		map[string]ir.Value{"encryption_info": blks(4, blk("client_broker", ks("PLAINTEXT", 5)))}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test345_TLSQuiet(t *testing.T) {
	f := runRule(mskNoEncryption{}, res("aws_msk_cluster", "kafka",
		map[string]ir.Value{"encryption_info": blks(4, blk("client_broker", ks("TLS", 5)))}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test345_UnknownQuiet(t *testing.T) {
	f := runRule(mskNoEncryption{}, res("aws_msk_cluster", "kafka",
		map[string]ir.Value{"encryption_info": blks(4, blk("client_broker", ku(5)))}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 346: CloudWatch log group without KMS encryption ---

func Test346_AbsentFires(t *testing.T) {
	f := runRule(cwLogGroupNoKMS{}, res("aws_cloudwatch_log_group", "app", map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test346_KeySetQuiet(t *testing.T) {
	f := runRule(cwLogGroupNoKMS{}, res("aws_cloudwatch_log_group", "app",
		map[string]ir.Value{"kms_key_id": ks("arn:aws:kms:us-east-1:123:key/abc", 3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test346_UnknownQuiet(t *testing.T) {
	f := runRule(cwLogGroupNoKMS{}, res("aws_cloudwatch_log_group", "app",
		map[string]ir.Value{"kms_key_id": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 347: CloudWatch log group without retention ---

func Test347_AbsentFires(t *testing.T) {
	f := runRule(cwLogGroupNoRetain{}, res("aws_cloudwatch_log_group", "app", map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test347_ZeroFires(t *testing.T) {
	f := runRule(cwLogGroupNoRetain{}, res("aws_cloudwatch_log_group", "app",
		map[string]ir.Value{"retention_in_days": kn(0, 3)}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test347_SetQuiet(t *testing.T) {
	f := runRule(cwLogGroupNoRetain{}, res("aws_cloudwatch_log_group", "app",
		map[string]ir.Value{"retention_in_days": kn(90, 3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test347_UnknownQuiet(t *testing.T) {
	f := runRule(cwLogGroupNoRetain{}, res("aws_cloudwatch_log_group", "app",
		map[string]ir.Value{"retention_in_days": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 348: GuardDuty detector disabled ---

func Test348_DisabledFires(t *testing.T) {
	f := runRule(guardDutyDisabled{}, res("aws_guardduty_detector", "main",
		map[string]ir.Value{"enable": kv(false, 3)}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test348_EnabledQuiet(t *testing.T) {
	f := runRule(guardDutyDisabled{}, res("aws_guardduty_detector", "main",
		map[string]ir.Value{"enable": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test348_UnknownQuiet(t *testing.T) {
	f := runRule(guardDutyDisabled{}, res("aws_guardduty_detector", "main",
		map[string]ir.Value{"enable": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 349: MQ broker without customer-managed encryption ---

func Test349_AbsentBlockFires(t *testing.T) {
	f := runRule(mqBrokerNoCMK{}, res("aws_mq_broker", "mq", map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test349_AWSOwnedKeyFires(t *testing.T) {
	f := runRule(mqBrokerNoCMK{}, res("aws_mq_broker", "mq",
		map[string]ir.Value{"encryption_options": blks(4, blk("use_aws_owned_key", kv(true, 5)))}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test349_CMKQuiet(t *testing.T) {
	f := runRule(mqBrokerNoCMK{}, res("aws_mq_broker", "mq",
		map[string]ir.Value{"encryption_options": blks(4,
			blk("use_aws_owned_key", kv(false, 5), "kms_key_id", ks("arn:aws:kms:us-east-1:123:key/abc", 6)))}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test349_UnknownQuiet(t *testing.T) {
	f := runRule(mqBrokerNoCMK{}, res("aws_mq_broker", "mq",
		map[string]ir.Value{"encryption_options": blks(4, blk("use_aws_owned_key", ku(5)))}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- 350: Kinesis stream without encryption ---

func Test350_AbsentFires(t *testing.T) {
	f := runRule(kinesisNoEncryption{}, res("aws_kinesis_stream", "events", map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test350_NoneFires(t *testing.T) {
	f := runRule(kinesisNoEncryption{}, res("aws_kinesis_stream", "events",
		map[string]ir.Value{"encryption_type": ks("NONE", 3)}))
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
}

func Test350_KMSQuiet(t *testing.T) {
	f := runRule(kinesisNoEncryption{}, res("aws_kinesis_stream", "events",
		map[string]ir.Value{"encryption_type": ks("KMS", 3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

func Test350_UnknownQuiet(t *testing.T) {
	f := runRule(kinesisNoEncryption{}, res("aws_kinesis_stream", "events",
		map[string]ir.Value{"encryption_type": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("got %d findings, want 0", len(f))
	}
}

// --- MessagingRules registry ---

func TestMessagingRules_OrderAndCount(t *testing.T) {
	rules := MessagingRules()
	if len(rules) != 10 {
		t.Fatalf("got %d rules, want 10", len(rules))
	}
	want := []string{
		"AEGIS-AWS-341", "AEGIS-AWS-342", "AEGIS-AWS-343", "AEGIS-AWS-344",
		"AEGIS-AWS-345", "AEGIS-AWS-346", "AEGIS-AWS-347", "AEGIS-AWS-348",
		"AEGIS-AWS-349", "AEGIS-AWS-350",
	}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Fatalf("position %d: got %s, want %s", i, r.ID(), want[i])
		}
		if i > 0 && rules[i-1].ID() >= r.ID() {
			t.Fatalf("rules not in ID order at %d", i)
		}
	}
}
