package aws

import (
	"testing"

	"aegis/internal/ir"
)

func num(v float64, line int) ir.Value { return ir.Value{Raw: v, Known: true, Span: spanAt(line)} }

// ---------------------------------------------------------------------------
// AEGIS-AWS-800
// ---------------------------------------------------------------------------

func TestBedrockNoTextLogging_FiresWhenAbsent(t *testing.T) {
	r := res("aws_bedrock_model_invocation_logging_configuration", "x",
		map[string]ir.Value{"logging_configurations": blks(2, blk("s3_configuration", blks(3)))})
	if f := runRule(bedrockNoTextLogging{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestBedrockNoTextLogging_PassesWithTextDelivery(t *testing.T) {
	r := res("aws_bedrock_model_invocation_logging_configuration", "x",
		map[string]ir.Value{"logging_configurations": blks(2, blk("text_data_delivery", blks(3, blk("enabled", kv(true, 4)))))})
	if f := runRule(bedrockNoTextLogging{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestBedrockNoTextLogging_UnknownBlockNoFinding(t *testing.T) {
	r := res("aws_bedrock_model_invocation_logging_configuration", "x",
		map[string]ir.Value{"logging_configurations": ku(2)})
	if f := runRule(bedrockNoTextLogging{}, r); len(f) != 0 {
		t.Fatalf("expected no findings on unknown, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-801
// ---------------------------------------------------------------------------

func TestBedrockNoContentPolicy_FiresWhenAbsent(t *testing.T) {
	r := res("aws_bedrock_guardrail", "x", map[string]ir.Value{})
	if f := runRule(bedrockNoContentPolicy{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestBedrockNoContentPolicy_PassesWithPolicy(t *testing.T) {
	r := res("aws_bedrock_guardrail", "x",
		map[string]ir.Value{"content_policy_config": blks(2, blk("filters_config", blks(3)))})
	if f := runRule(bedrockNoContentPolicy{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-802
// ---------------------------------------------------------------------------

func TestSagemakerNotebookInternet_FiresWhenEnabled(t *testing.T) {
	r := res("aws_sagemaker_notebook_instance", "x",
		map[string]ir.Value{"direct_internet_access": ks("Enabled", 2)})
	if f := runRule(sagemakerNotebookInternet{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestSagemakerNotebookInternet_PassesWhenDisabled(t *testing.T) {
	for _, cfg := range []map[string]ir.Value{
		{},
		{"direct_internet_access": ks("Disabled", 2)},
	} {
		r := res("aws_sagemaker_notebook_instance", "x", cfg)
		if f := runRule(sagemakerNotebookInternet{}, r); len(f) != 0 {
			t.Fatalf("expected no findings for %v, got %d", cfg, len(f))
		}
	}
}

func TestSagemakerNotebookInternet_UnknownNoFinding(t *testing.T) {
	r := res("aws_sagemaker_notebook_instance", "x",
		map[string]ir.Value{"direct_internet_access": ku(2)})
	if f := runRule(sagemakerNotebookInternet{}, r); len(f) != 0 {
		t.Fatalf("expected no findings on unknown, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-803
// ---------------------------------------------------------------------------

func TestSagemakerNotebookRootAccess_FiresOnEnabled(t *testing.T) {
	r := res("aws_sagemaker_notebook_instance", "x",
		map[string]ir.Value{"root_access": ks("Enabled", 2)})
	if f := runRule(sagemakerNotebookRootAccess{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestSagemakerNotebookRootAccess_FiresWhenAbsent(t *testing.T) {
	r := res("aws_sagemaker_notebook_instance", "x", map[string]ir.Value{})
	if f := runRule(sagemakerNotebookRootAccess{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestSagemakerNotebookRootAccess_PassesWhenDisabled(t *testing.T) {
	r := res("aws_sagemaker_notebook_instance", "x",
		map[string]ir.Value{"root_access": ks("Disabled", 2)})
	if f := runRule(sagemakerNotebookRootAccess{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-804
// ---------------------------------------------------------------------------

func TestSagemakerEndpointNoCapture_FiresWhenAbsent(t *testing.T) {
	r := res("aws_sagemaker_endpoint_configuration", "x", map[string]ir.Value{})
	if f := runRule(sagemakerEndpointNoCapture{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestSagemakerEndpointNoCapture_PassesWithCapture(t *testing.T) {
	r := res("aws_sagemaker_endpoint_configuration", "x",
		map[string]ir.Value{"data_capture_config": blks(2, blk("destination_s3_uri", ks("s3://x", 3)))})
	if f := runRule(sagemakerEndpointNoCapture{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-805
// ---------------------------------------------------------------------------

func TestSagemakerDomainPublicAccess_FiresWhenAbsent(t *testing.T) {
	r := res("aws_sagemaker_domain", "x", map[string]ir.Value{})
	if f := runRule(sagemakerDomainPublicAccess{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestSagemakerDomainPublicAccess_PassesOnVpcOnly(t *testing.T) {
	r := res("aws_sagemaker_domain", "x",
		map[string]ir.Value{"app_network_access_type": ks("VpcOnly", 2)})
	if f := runRule(sagemakerDomainPublicAccess{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestSagemakerDomainPublicAccess_UnknownNoFinding(t *testing.T) {
	r := res("aws_sagemaker_domain", "x",
		map[string]ir.Value{"app_network_access_type": ku(2)})
	if f := runRule(sagemakerDomainPublicAccess{}, r); len(f) != 0 {
		t.Fatalf("expected no findings on unknown, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-806
// ---------------------------------------------------------------------------

func TestEventArchiveNoRetention_FiresOnZero(t *testing.T) {
	r := res("aws_events_archive", "x",
		map[string]ir.Value{"retention_days": num(0, 2)})
	if f := runRule(eventArchiveNoRetention{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestEventArchiveNoRetention_PassesWhenSet(t *testing.T) {
	r := res("aws_events_archive", "x",
		map[string]ir.Value{"retention_days": num(30, 2)})
	if f := runRule(eventArchiveNoRetention{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-807
// ---------------------------------------------------------------------------

func TestSchedulerNoKMS_FiresWhenAbsent(t *testing.T) {
	r := res("aws_scheduler_schedule", "x", map[string]ir.Value{})
	if f := runRule(schedulerNoKMS{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestSchedulerNoKMS_PassesWithKey(t *testing.T) {
	r := res("aws_scheduler_schedule", "x",
		map[string]ir.Value{"kms_key_arn": ks("arn:aws:kms:us-east-1:1:key/abc", 2)})
	if f := runRule(schedulerNoKMS{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-808
// ---------------------------------------------------------------------------

func TestMSKPlaintextBrokers_FiresOnPlaintext(t *testing.T) {
	r := res("aws_msk_cluster", "x",
		map[string]ir.Value{"encryption_info": blks(2, blk("client_broker", ks("PLAINTEXT", 3)))})
	if f := runRule(mskPlaintextBrokers{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestMSKPlaintextBrokers_PassesOnTLS(t *testing.T) {
	for _, cfg := range []map[string]ir.Value{
		{},
		{"encryption_info": blks(2, blk("client_broker", ks("TLS", 3)))},
	} {
		r := res("aws_msk_cluster", "x", cfg)
		if f := runRule(mskPlaintextBrokers{}, r); len(f) != 0 {
			t.Fatalf("expected no findings for %v, got %d", cfg, len(f))
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-809
// ---------------------------------------------------------------------------

func TestMSKWeakMonitoring_FiresOnDefault(t *testing.T) {
	r := res("aws_msk_cluster", "x",
		map[string]ir.Value{"enhanced_monitoring": ks("DEFAULT", 2)})
	if f := runRule(mskWeakMonitoring{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestMSKWeakMonitoring_FiresWhenAbsent(t *testing.T) {
	r := res("aws_msk_cluster", "x", map[string]ir.Value{})
	if f := runRule(mskWeakMonitoring{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestMSKWeakMonitoring_PassesPerTopic(t *testing.T) {
	r := res("aws_msk_cluster", "x",
		map[string]ir.Value{"enhanced_monitoring": ks("PER_TOPIC_PER_BROKER", 2)})
	if f := runRule(mskWeakMonitoring{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-810
// ---------------------------------------------------------------------------

func TestMSKFewBrokers_FiresBelowThree(t *testing.T) {
	r := res("aws_msk_cluster", "x",
		map[string]ir.Value{"number_of_broker_nodes": num(2, 2)})
	if f := runRule(mskFewBrokers{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestMSKFewBrokers_PassesAtThree(t *testing.T) {
	r := res("aws_msk_cluster", "x",
		map[string]ir.Value{"number_of_broker_nodes": num(3, 2)})
	if f := runRule(mskFewBrokers{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-811
// ---------------------------------------------------------------------------

func TestOpensearchNoAdvSecurity_FiresWhenAbsent(t *testing.T) {
	r := res("aws_opensearch_domain", "x", map[string]ir.Value{})
	if f := runRule(opensearchNoAdvSecurity{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestOpensearchNoAdvSecurity_FiresWhenDisabled(t *testing.T) {
	r := res("aws_opensearch_domain", "x",
		map[string]ir.Value{"advanced_security_options": blks(2, blk("enabled", kv(false, 3)))})
	if f := runRule(opensearchNoAdvSecurity{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestOpensearchNoAdvSecurity_PassesWhenEnabled(t *testing.T) {
	r := res("aws_opensearch_domain", "x",
		map[string]ir.Value{"advanced_security_options": blks(2, blk("enabled", kv(true, 3)))})
	if f := runRule(opensearchNoAdvSecurity{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-812
// ---------------------------------------------------------------------------

func TestOpensearchNoLogPublishing_FiresWhenAbsent(t *testing.T) {
	r := res("aws_opensearch_domain", "x", map[string]ir.Value{})
	if f := runRule(opensearchNoLogPublishing{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestOpensearchNoLogPublishing_PassesWithOptions(t *testing.T) {
	r := res("aws_opensearch_domain", "x",
		map[string]ir.Value{"log_publishing_options": blks(2, blk("log_type", ks("AUDIT_LOGS", 3)))})
	if f := runRule(opensearchNoLogPublishing{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-813
// ---------------------------------------------------------------------------

func TestNeptuneSkipFinalSnapshot_FiresWhenTrue(t *testing.T) {
	r := res("aws_neptune_cluster", "x",
		map[string]ir.Value{"skip_final_snapshot": kv(true, 2)})
	if f := runRule(neptuneSkipFinalSnapshot{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestNeptuneSkipFinalSnapshot_PassesWhenAbsent(t *testing.T) {
	r := res("aws_neptune_cluster", "x", map[string]ir.Value{})
	if f := runRule(neptuneSkipFinalSnapshot{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-814
// ---------------------------------------------------------------------------

func TestNeptuneNoCopyTags_FiresWhenAbsent(t *testing.T) {
	r := res("aws_neptune_cluster", "x", map[string]ir.Value{})
	if f := runRule(neptuneNoCopyTags{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestNeptuneNoCopyTags_PassesWhenTrue(t *testing.T) {
	r := res("aws_neptune_cluster", "x",
		map[string]ir.Value{"copy_tags_to_snapshot": kv(true, 2)})
	if f := runRule(neptuneNoCopyTags{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-430
// ---------------------------------------------------------------------------

func TestDocdbNoDeletionProt_FiresWhenAbsent(t *testing.T) {
	r := res("aws_docdb_cluster", "x", map[string]ir.Value{})
	if f := runRule(docdbNoDeletionProtection{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestDocdbNoDeletionProt_PassesWhenTrue(t *testing.T) {
	r := res("aws_docdb_cluster", "x",
		map[string]ir.Value{"deletion_protection": kv(true, 2)})
	if f := runRule(docdbNoDeletionProtection{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-816
// ---------------------------------------------------------------------------

func TestApprunnerNoEncryption_FiresWhenAbsent(t *testing.T) {
	r := res("aws_apprunner_service", "x", map[string]ir.Value{})
	if f := runRule(apprunnerNoEncryption{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApprunnerNoEncryption_PassesWithConfig(t *testing.T) {
	r := res("aws_apprunner_service", "x",
		map[string]ir.Value{"encryption_configuration": blks(2, blk("kms_key", ks("arn:aws:kms:..", 3)))})
	if f := runRule(apprunnerNoEncryption{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-817
// ---------------------------------------------------------------------------

func TestApprunnerRootHealthCheck_FiresOnRootPath(t *testing.T) {
	r := res("aws_apprunner_service", "x",
		map[string]ir.Value{"health_check": blks(2, blk("path", ks("/", 3)))})
	if f := runRule(apprunnerRootHealthCheck{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApprunnerRootHealthCheck_PassesOnDedicatedPath(t *testing.T) {
	r := res("aws_apprunner_service", "x",
		map[string]ir.Value{"health_check": blks(2, blk("path", ks("/healthz", 3)))})
	if f := runRule(apprunnerRootHealthCheck{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-818
// ---------------------------------------------------------------------------

func TestBatchJobPrivileged_FiresOnJSONString(t *testing.T) {
	r := res("aws_batch_job_definition", "x",
		map[string]ir.Value{"container_properties": ks(`{"privileged": true, "image": "x"}`, 2)})
	if f := runRule(batchJobPrivileged{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestBatchJobPrivileged_PassesWithoutPrivileged(t *testing.T) {
	r := res("aws_batch_job_definition", "x",
		map[string]ir.Value{"container_properties": ks(`{"image": "x"}`, 2)})
	if f := runRule(batchJobPrivileged{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestBatchJobPrivileged_UnknownNoFinding(t *testing.T) {
	r := res("aws_batch_job_definition", "x",
		map[string]ir.Value{"container_properties": ku(2)})
	if f := runRule(batchJobPrivileged{}, r); len(f) != 0 {
		t.Fatalf("expected no findings on unknown, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-819
// ---------------------------------------------------------------------------

func TestGlueNoSecurityConfig_FiresWhenAbsent(t *testing.T) {
	r := res("aws_glue_security_configuration", "x", map[string]ir.Value{})
	if f := runRule(glueNoSecurityConfig{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGlueNoSecurityConfig_PassesWithEncryption(t *testing.T) {
	r := res("aws_glue_security_configuration", "x",
		map[string]ir.Value{"encryption_configuration": blks(2, blk("cloudwatch_encryption", blks(3)))})
	if f := runRule(glueNoSecurityConfig{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-820
// ---------------------------------------------------------------------------

func TestAthenaWorkgroupNoKMS_FiresWhenAbsent(t *testing.T) {
	r := res("aws_athena_workgroup", "x", map[string]ir.Value{})
	if f := runRule(athenaWorkgroupNoKMS{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestAthenaWorkgroupNoKMS_FiresOnSSES3(t *testing.T) {
	r := res("aws_athena_workgroup", "x",
		map[string]ir.Value{"configuration": blks(2,
			blk("result_configuration", blks(3,
				blk("encryption_configuration", blks(4,
					blk("encryption_option", ks("SSE_S3", 5)))))))})
	if f := runRule(athenaWorkgroupNoKMS{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestAthenaWorkgroupNoKMS_PassesOnSSEKMS(t *testing.T) {
	r := res("aws_athena_workgroup", "x",
		map[string]ir.Value{"configuration": blks(2,
			blk("result_configuration", blks(3,
				blk("encryption_configuration", blks(4,
					blk("encryption_option", ks("SSE_KMS", 5)))))))})
	if f := runRule(athenaWorkgroupNoKMS{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-821
// ---------------------------------------------------------------------------

func TestAthenaNoEnforceWorkgroup_FiresWhenFalse(t *testing.T) {
	r := res("aws_athena_workgroup", "x",
		map[string]ir.Value{"configuration": blks(2,
			blk("enforce_workgroup_configuration", kv(false, 3)))})
	if f := runRule(athenaNoEnforceWorkgroup{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestAthenaNoEnforceWorkgroup_PassesWhenTrue(t *testing.T) {
	r := res("aws_athena_workgroup", "x",
		map[string]ir.Value{"configuration": blks(2,
			blk("enforce_workgroup_configuration", kv(true, 3)))})
	if f := runRule(athenaNoEnforceWorkgroup{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-822
// ---------------------------------------------------------------------------

func TestKinesisNoShardMetrics_FiresWhenAbsent(t *testing.T) {
	r := res("aws_kinesis_stream", "x", map[string]ir.Value{})
	if f := runRule(kinesisNoShardMetrics{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestKinesisNoShardMetrics_FiresOnEmpty(t *testing.T) {
	r := res("aws_kinesis_stream", "x",
		map[string]ir.Value{"shard_level_metrics": strList(2)})
	if f := runRule(kinesisNoShardMetrics{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestKinesisNoShardMetrics_PassesWithMetrics(t *testing.T) {
	r := res("aws_kinesis_stream", "x",
		map[string]ir.Value{"shard_level_metrics": strList(2, "IncomingBytes")})
	if f := runRule(kinesisNoShardMetrics{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-823
// ---------------------------------------------------------------------------

func TestFirehoseNoSSE_FiresWhenAbsent(t *testing.T) {
	r := res("aws_kinesis_firehose_delivery_stream", "x", map[string]ir.Value{})
	if f := runRule(firehoseNoSSE{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestFirehoseNoSSE_PassesWithSSE(t *testing.T) {
	r := res("aws_kinesis_firehose_delivery_stream", "x",
		map[string]ir.Value{"server_side_encryption": blks(2, blk("enabled", kv(true, 3)))})
	if f := runRule(firehoseNoSSE{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-824
// ---------------------------------------------------------------------------

func TestTimestreamQueryReportNoKMS_FiresOnSSES3(t *testing.T) {
	r := res("aws_timestreamquery_scheduled_query", "x",
		map[string]ir.Value{"error_report_configuration": blks(2,
			blk("s3_configuration", blks(3,
				blk("encryption_option", ks("SSE_S3", 4)))))})
	if f := runRule(timestreamQueryReportNoKMS{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestTimestreamQueryReportNoKMS_FiresWhenOptionAbsent(t *testing.T) {
	r := res("aws_timestreamquery_scheduled_query", "x",
		map[string]ir.Value{"error_report_configuration": blks(2,
			blk("s3_configuration", blks(3,
				blk("bucket_name", ks("reports", 4)))))})
	if f := runRule(timestreamQueryReportNoKMS{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestTimestreamQueryReportNoKMS_PassesOnSSEKMS(t *testing.T) {
	r := res("aws_timestreamquery_scheduled_query", "x",
		map[string]ir.Value{"error_report_configuration": blks(2,
			blk("s3_configuration", blks(3,
				blk("encryption_option", ks("SSE_KMS", 4)))))})
	if f := runRule(timestreamQueryReportNoKMS{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestTimestreamQueryReportNoKMS_PassesWithoutErrorReports(t *testing.T) {
	r := res("aws_timestreamquery_scheduled_query", "x", map[string]ir.Value{})
	if f := runRule(timestreamQueryReportNoKMS{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// Registration sanity: all 25 rules present, IDs unique and ordered.
// ---------------------------------------------------------------------------

func TestServicesDeepRules_AllIDs(t *testing.T) {
	rules := ServicesDeepRules()
	if len(rules) != 24 {
		t.Fatalf("expected 24 rules, got %d", len(rules))
	}
	seen := map[string]bool{}
	prev := ""
	for _, r := range rules {
		id := r.ID()
		if seen[id] {
			t.Fatalf("duplicate rule ID %s", id)
		}
		seen[id] = true
		if prev != "" && id <= prev {
			t.Fatalf("rules not in ID order: %s after %s", prev, id)
		}
		prev = id
	}
	want := []string{"AEGIS-AWS-800", "AEGIS-AWS-824"}
	for _, w := range want {
		if !seen[w] {
			t.Fatalf("missing rule %s", w)
		}
	}
}
