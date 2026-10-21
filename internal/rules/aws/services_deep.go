package aws

// Newer-service hardening, deep round (AEGIS-AWS-800..824).
//
// Covers Bedrock (invocation logging, guardrails), SageMaker (notebook
// internet access, KMS), EventBridge archives, EventBridge Scheduler, MSK
// (plaintext brokers, monitoring, broker count), OpenSearch (advanced
// security, log publishing), Neptune (IAM auth, snapshot tags), DocumentDB
// (deletion protection), App Runner (encryption, health check), Batch (job
// privileged mode), Glue (security configuration), Athena (workgroup
// encryption, enforcement), Kinesis (stream encryption), Firehose (server-side
// encryption) and Timestream (KMS).
//
// Unknown-value contract: a present-but-unresolved attribute yields NO
// finding. Absent attributes are judged against the provider's documented
// insecure default, documented per rule. Rules never panic on unexpected
// shapes.

import (
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// ServicesDeepRules returns the newer-services deep rules, AEGIS-AWS-800..824,
// in ID order.
func ServicesDeepRules() []ir.Rule {
	return []ir.Rule{
		bedrockNoTextLogging{},        // AEGIS-AWS-800
		bedrockNoContentPolicy{},      // AEGIS-AWS-801
		sagemakerNotebookInternet{},   // AEGIS-AWS-802
		sagemakerNotebookRootAccess{}, // AEGIS-AWS-803
		sagemakerEndpointNoCapture{},  // AEGIS-AWS-804
		sagemakerDomainPublicAccess{}, // AEGIS-AWS-805
		eventArchiveNoRetention{},     // AEGIS-AWS-806
		schedulerNoKMS{},              // AEGIS-AWS-807
		mskPlaintextBrokers{},         // AEGIS-AWS-808
		mskWeakMonitoring{},           // AEGIS-AWS-809
		mskFewBrokers{},               // AEGIS-AWS-810
		neptuneSkipFinalSnapshot{},    // AEGIS-AWS-813
		neptuneNoCopyTags{},           // AEGIS-AWS-814
		apprunnerNoEncryption{},       // AEGIS-AWS-816
		apprunnerRootHealthCheck{},    // AEGIS-AWS-817
		batchJobPrivileged{},          // AEGIS-AWS-818
		glueNoSecurityConfig{},        // AEGIS-AWS-819
		athenaWorkgroupNoKMS{},        // AEGIS-AWS-820
		athenaNoEnforceWorkgroup{},    // AEGIS-AWS-821
		kinesisNoShardMetrics{},       // AEGIS-AWS-822
		firehoseNoSSE{},               // AEGIS-AWS-823
		timestreamQueryReportNoKMS{},  // AEGIS-AWS-824
	}
}

// sdFinding builds a finding for the services-deep rules.
func sdFinding(rule ir.Rule, r ir.Resource, attr string, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
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
	}
}

// blockAbsent reports whether a named sub-block is missing from a block map.
// An unknown (unresolved) value is undecidable: (false, false).
func blockAbsent(m map[string]ir.Value, name string) (absent, decidable bool) {
	v, ok := m[name]
	if !ok {
		return true, true
	}
	if !v.Known {
		return false, false
	}
	if l, ok := v.AsList(); ok {
		return len(l) == 0, true
	}
	if _, ok := v.AsMap(); ok {
		return false, true
	}
	return false, true
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-800: Bedrock invocation logging without text data delivery
// ---------------------------------------------------------------------------

type bedrockNoTextLogging struct{}

func (bedrockNoTextLogging) ID() string { return "AEGIS-AWS-800" }
func (bedrockNoTextLogging) Title() string {
	return "Bedrock invocation logging without text data delivery"
}
func (bedrockNoTextLogging) Description() string {
	return "A Bedrock model invocation logging configuration whose " +
		"logging_configurations block omits text_data_delivery captures no " +
		"prompt/completion text, leaving AI safety incidents without an " +
		"auditable record. Enable text data delivery to a logging destination."
}
func (bedrockNoTextLogging) Severity() ir.Severity { return ir.SeverityMedium }
func (bedrockNoTextLogging) AppliesTo(resType string) bool {
	return resType == "aws_bedrock_model_invocation_logging_configuration"
}

func (s bedrockNoTextLogging) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "logging_configurations")
	if present && !known {
		return nil // unresolved block: cannot decide
	}
	if !present || len(blks) == 0 {
		return absentInsecureDefault(s, r,
			"logging_configurations.text_data_delivery",
			"absent (no text logging configured)",
			"logging_configurations { text_data_delivery { ... } }")
	}
	absent, decidable := blockAbsent(blks[0], "text_data_delivery")
	if !decidable {
		return nil
	}
	if !absent {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "logging_configurations.text_data_delivery",
		ir.Span{}, "absent",
		"logging_configurations { text_data_delivery { ... } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-801: Bedrock guardrail without content policy
// ---------------------------------------------------------------------------

type bedrockNoContentPolicy struct{}

func (bedrockNoContentPolicy) ID() string { return "AEGIS-AWS-801" }
func (bedrockNoContentPolicy) Title() string {
	return "Bedrock guardrail without a content policy"
}
func (bedrockNoContentPolicy) Description() string {
	return "A Bedrock guardrail with no content_policy_config block cannot " +
		"filter harmful, hateful or violent model output. Add a content " +
		"policy with filters tuned to the application's risk profile."
}
func (bedrockNoContentPolicy) Severity() ir.Severity { return ir.SeverityMedium }
func (bedrockNoContentPolicy) AppliesTo(resType string) bool {
	return resType == "aws_bedrock_guardrail"
}

func (s bedrockNoContentPolicy) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "content_policy_config")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return absentInsecureDefault(s, r, "content_policy_config",
		"absent (no content filtering)", "content_policy_config { filters_config { ... } }")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-802: SageMaker notebook with direct internet access
// ---------------------------------------------------------------------------

type sagemakerNotebookInternet struct{}

func (sagemakerNotebookInternet) ID() string { return "AEGIS-AWS-802" }
func (sagemakerNotebookInternet) Title() string {
	return "SageMaker notebook instance with direct internet access"
}
func (sagemakerNotebookInternet) Description() string {
	return "A SageMaker notebook instance with direct_internet_access = " +
		"\"Enabled\" can reach the public internet without a VPC, letting " +
		"training data and credentials exfiltrate directly. Disable direct " +
		"internet access and route traffic through a VPC."
}
func (sagemakerNotebookInternet) Severity() ir.Severity { return ir.SeverityHigh }
func (sagemakerNotebookInternet) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_notebook_instance"
}

func (s sagemakerNotebookInternet) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "direct_internet_access")
	if !present || !known {
		return nil // provider default is Disabled: absent is safe
	}
	if val != "Enabled" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "direct_internet_access", span,
		"\"Enabled\"", "direct_internet_access = \"Disabled\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-803: SageMaker notebook instance with root access enabled
// ---------------------------------------------------------------------------
//
// (The kms_key_id check already exists as AEGIS-AWS-366; this rule covers
// the distinct root-access gap instead of duplicating it.)

type sagemakerNotebookRootAccess struct{}

func (sagemakerNotebookRootAccess) ID() string { return "AEGIS-AWS-803" }
func (sagemakerNotebookRootAccess) Title() string {
	return "SageMaker notebook instance with root access enabled"
}
func (sagemakerNotebookRootAccess) Description() string {
	return "A SageMaker notebook instance with root_access enabled (the " +
		"provider default) lets users log in as root, bypassing the notebook " +
		"execution role's least-privilege boundary. Set root_access = " +
		"\"Disabled\" unless root shell access is required."
}
func (sagemakerNotebookRootAccess) Severity() ir.Severity { return ir.SeverityMedium }
func (sagemakerNotebookRootAccess) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_notebook_instance"
}

func (s sagemakerNotebookRootAccess) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "root_access")
	if present && !known {
		return nil
	}
	if !present {
		return absentInsecureDefault(s, r, "root_access",
			"absent (provider default: Enabled)", "root_access = \"Disabled\"")
	}
	if val != "Enabled" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "root_access", span,
		"\"Enabled\"", "root_access = \"Disabled\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-804: SageMaker endpoint configuration without data capture
// ---------------------------------------------------------------------------
//
// (The kms_key_arn check already exists as AEGIS-AWS-367; this rule covers
// the distinct data-capture gap instead of duplicating it.)

type sagemakerEndpointNoCapture struct{}

func (sagemakerEndpointNoCapture) ID() string { return "AEGIS-AWS-804" }
func (sagemakerEndpointNoCapture) Title() string {
	return "SageMaker endpoint configuration without data capture"
}
func (sagemakerEndpointNoCapture) Description() string {
	return "A SageMaker endpoint configuration with no data_capture_config " +
		"block records no request/response payloads, leaving model drift, " +
		"bias and abuse without an auditable trail. Enable data capture to " +
		"S3 for production endpoints."
}
func (sagemakerEndpointNoCapture) Severity() ir.Severity { return ir.SeverityLow }
func (sagemakerEndpointNoCapture) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_endpoint_configuration"
}

func (s sagemakerEndpointNoCapture) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "data_capture_config")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return absentInsecureDefault(s, r, "data_capture_config",
		"absent (no inference data captured)",
		"data_capture_config { destination_s3_uri = ... }")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-805: SageMaker domain allowing public internet app access
// ---------------------------------------------------------------------------
//
// (The kms_key_id check already exists as AEGIS-AWS-370; this rule covers
// the distinct network-access gap instead of duplicating it.)

type sagemakerDomainPublicAccess struct{}

func (sagemakerDomainPublicAccess) ID() string { return "AEGIS-AWS-805" }
func (sagemakerDomainPublicAccess) Title() string {
	return "SageMaker domain allowing public internet app access"
}
func (sagemakerDomainPublicAccess) Description() string {
	return "A SageMaker domain with app_network_access_type = " +
		"\"PublicInternetOnly\" (the provider default) lets Studio apps reach " +
		"the public internet directly, bypassing VPC egress controls. Use " +
		"\"VpcOnly\" with VPC endpoints for production domains."
}
func (sagemakerDomainPublicAccess) Severity() ir.Severity { return ir.SeverityMedium }
func (sagemakerDomainPublicAccess) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_domain"
}

func (s sagemakerDomainPublicAccess) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "app_network_access_type")
	if present && !known {
		return nil
	}
	if !present {
		return absentInsecureDefault(s, r, "app_network_access_type",
			"absent (provider default: PublicInternetOnly)",
			"app_network_access_type = \"VpcOnly\"")
	}
	if val != "PublicInternetOnly" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "app_network_access_type", span,
		"\"PublicInternetOnly\"", "app_network_access_type = \"VpcOnly\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-806: EventBridge archive with zero retention
// ---------------------------------------------------------------------------

type eventArchiveNoRetention struct{}

func (eventArchiveNoRetention) ID() string { return "AEGIS-AWS-806" }
func (eventArchiveNoRetention) Title() string {
	return "EventBridge archive with zero-day retention"
}
func (eventArchiveNoRetention) Description() string {
	return "An EventBridge archive with retention_days = 0 keeps events only " +
		"for the transient default window, leaving no replayable record for " +
		"incident investigation. Set retention_days to a value matching the " +
		"organization's audit retention policy."
}
func (eventArchiveNoRetention) Severity() ir.Severity { return ir.SeverityLow }
func (eventArchiveNoRetention) AppliesTo(resType string) bool {
	return resType == "aws_events_archive"
}

func (s eventArchiveNoRetention) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNumber(r, "retention_days")
	if !present || !known {
		return nil
	}
	if days != 0 {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "retention_days", span,
		"0", "retention_days = <audit retention period>")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-807: EventBridge Scheduler schedule without KMS key
// ---------------------------------------------------------------------------

type schedulerNoKMS struct{}

func (schedulerNoKMS) ID() string { return "AEGIS-AWS-807" }
func (schedulerNoKMS) Title() string {
	return "EventBridge Scheduler schedule without a KMS key"
}
func (schedulerNoKMS) Description() string {
	return "An EventBridge Scheduler schedule with no kms_key_arn stores its " +
		"payload and configuration with an AWS-managed key. Set kms_key_arn " +
		"to a customer managed key when schedules carry sensitive payloads."
}
func (schedulerNoKMS) Severity() ir.Severity { return ir.SeverityLow }
func (schedulerNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_scheduler_schedule"
}

func (s schedulerNoKMS) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "kms_key_arn")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return absentInsecureDefault(s, r, "kms_key_arn",
		"absent (AWS-managed key)", "kms_key_arn = <customer managed key>")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-808: MSK cluster with plaintext client-broker encryption
// ---------------------------------------------------------------------------

type mskPlaintextBrokers struct{}

func (mskPlaintextBrokers) ID() string { return "AEGIS-AWS-808" }
func (mskPlaintextBrokers) Title() string {
	return "MSK cluster allowing plaintext client-broker traffic"
}
func (mskPlaintextBrokers) Description() string {
	return "An MSK cluster whose encryption_info sets client_broker = " +
		"\"PLAINTEXT\" lets clients exchange Kafka records unencrypted, " +
		"exposing data and SASL credentials to network sniffing. Use " +
		"TLS_PLAINTEXT or TLS."
}
func (mskPlaintextBrokers) Severity() ir.Severity { return ir.SeverityHigh }
func (mskPlaintextBrokers) AppliesTo(resType string) bool {
	return resType == "aws_msk_cluster"
}

func (s mskPlaintextBrokers) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "encryption_info")
	if !present || !known || len(blks) == 0 {
		return nil // provider default is TLS_PLAINTEXT: absent is safe
	}
	val, span, vpresent, vknown := blockString(blks[0], "client_broker")
	if !vpresent || !vknown {
		return nil
	}
	if val != "PLAINTEXT" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "encryption_info.client_broker", span,
		"\"PLAINTEXT\"", "client_broker = \"TLS\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-809: MSK cluster without per-topic enhanced monitoring
// ---------------------------------------------------------------------------

type mskWeakMonitoring struct{}

func (mskWeakMonitoring) ID() string { return "AEGIS-AWS-809" }
func (mskWeakMonitoring) Title() string {
	return "MSK cluster without per-topic enhanced monitoring"
}
func (mskWeakMonitoring) Description() string {
	return "An MSK cluster whose enhanced_monitoring is not " +
		"PER_TOPIC_PER_BROKER emits only coarse cluster metrics, hiding " +
		"per-topic anomalies that signal misuse or exfiltration. Enable " +
		"PER_TOPIC_PER_BROKER monitoring."
}
func (mskWeakMonitoring) Severity() ir.Severity { return ir.SeverityLow }
func (mskWeakMonitoring) AppliesTo(resType string) bool {
	return resType == "aws_msk_cluster"
}

func (s mskWeakMonitoring) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "enhanced_monitoring")
	if present && !known {
		return nil
	}
	if present && val == "PER_TOPIC_PER_BROKER" {
		return nil
	}
	if !present {
		return absentInsecureDefault(s, r, "enhanced_monitoring",
			"absent (provider default: DEFAULT)",
			"enhanced_monitoring = \"PER_TOPIC_PER_BROKER\"")
	}
	return []ir.Finding{sdFinding(s, r, "enhanced_monitoring", span,
		"\""+val+"\"", "enhanced_monitoring = \"PER_TOPIC_PER_BROKER\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-810: MSK cluster with fewer than three broker nodes
// ---------------------------------------------------------------------------

type mskFewBrokers struct{}

func (mskFewBrokers) ID() string { return "AEGIS-AWS-810" }
func (mskFewBrokers) Title() string {
	return "MSK cluster with fewer than three broker nodes"
}
func (mskFewBrokers) Description() string {
	return "An MSK cluster with number_of_broker_nodes below 3 cannot " +
		"sustain a broker failure without losing partition availability, and " +
		"single-AZ deployments concentrate blast radius. Run at least three " +
		"brokers spread across availability zones."
}
func (mskFewBrokers) Severity() ir.Severity { return ir.SeverityMedium }
func (mskFewBrokers) AppliesTo(resType string) bool {
	return resType == "aws_msk_cluster"
}

func (s mskFewBrokers) Check(r ir.Resource) []ir.Finding {
	n, span, present, known := getNumber(r, "number_of_broker_nodes")
	if !present || !known {
		return nil
	}
	if n >= 3 {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "number_of_broker_nodes", span,
		trimFloat(n), "number_of_broker_nodes >= 3")}
}

// trimFloat renders a whole float without a trailing ".0".
func trimFloat(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-811: OpenSearch without fine-grained access control

// ---------------------------------------------------------------------------
// AEGIS-AWS-812: OpenSearch without log publishing

// ---------------------------------------------------------------------------
// AEGIS-AWS-813: Neptune cluster skipping the final snapshot
// ---------------------------------------------------------------------------
//
// (The IAM database authentication check already exists as AEGIS-AWS-522;
// this rule covers the distinct final-snapshot gap instead of duplicating
// it.)

type neptuneSkipFinalSnapshot struct{}

func (neptuneSkipFinalSnapshot) ID() string { return "AEGIS-AWS-813" }
func (neptuneSkipFinalSnapshot) Title() string {
	return "Neptune cluster skipping the final snapshot"
}
func (neptuneSkipFinalSnapshot) Description() string {
	return "A Neptune cluster with skip_final_snapshot = true destroys all " +
		"graph data on cluster deletion with no final backup, making " +
		"accidental or malicious deletion unrecoverable. Keep " +
		"skip_final_snapshot = false (the default) on production clusters."
}
func (neptuneSkipFinalSnapshot) Severity() ir.Severity { return ir.SeverityMedium }
func (neptuneSkipFinalSnapshot) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}

func (s neptuneSkipFinalSnapshot) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "skip_final_snapshot")
	if !present || !known {
		return nil // provider default is false: absent is safe
	}
	if !val {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "skip_final_snapshot", span,
		"true", "skip_final_snapshot = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-814: Neptune cluster not copying tags to snapshots
// ---------------------------------------------------------------------------

type neptuneNoCopyTags struct{}

func (neptuneNoCopyTags) ID() string { return "AEGIS-AWS-814" }
func (neptuneNoCopyTags) Title() string {
	return "Neptune cluster not copying tags to snapshots"
}
func (neptuneNoCopyTags) Description() string {
	return "A Neptune cluster with copy_tags_to_snapshot = false (the " +
		"default) produces untagged snapshots, breaking cost allocation and " +
		"data-classification tagging on backups. Set " +
		"copy_tags_to_snapshot = true."
}
func (neptuneNoCopyTags) Severity() ir.Severity { return ir.SeverityLow }
func (neptuneNoCopyTags) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}

func (s neptuneNoCopyTags) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "copy_tags_to_snapshot")
	if present && !known {
		return nil
	}
	if present && val {
		return nil
	}
	if !present {
		return absentInsecureDefault(s, r, "copy_tags_to_snapshot",
			"absent (provider default: false)", "copy_tags_to_snapshot = true")
	}
	return []ir.Finding{sdFinding(s, r, "copy_tags_to_snapshot",
		span, "false", "copy_tags_to_snapshot = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-815: DocumentDB cluster without deletion protection
// ---------------------------------------------------------------------------
// AEGIS-AWS-816: App Runner service without encryption configuration
// ---------------------------------------------------------------------------

type apprunnerNoEncryption struct{}

func (apprunnerNoEncryption) ID() string { return "AEGIS-AWS-816" }
func (apprunnerNoEncryption) Title() string {
	return "App Runner service without encryption configuration"
}
func (apprunnerNoEncryption) Description() string {
	return "An App Runner service with no encryption_configuration block " +
		"encrypts stored data with an AWS-managed key instead of a customer " +
		"managed key. Add encryption_configuration with a customer KMS key."
}
func (apprunnerNoEncryption) Severity() ir.Severity { return ir.SeverityMedium }
func (apprunnerNoEncryption) AppliesTo(resType string) bool {
	return resType == "aws_apprunner_service"
}

func (s apprunnerNoEncryption) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "encryption_configuration")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return absentInsecureDefault(s, r, "encryption_configuration",
		"absent (AWS-managed key)",
		"encryption_configuration { kms_key = <customer managed key> }")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-817: App Runner service with root-path health check
// ---------------------------------------------------------------------------

type apprunnerRootHealthCheck struct{}

func (apprunnerRootHealthCheck) ID() string { return "AEGIS-AWS-817" }
func (apprunnerRootHealthCheck) Title() string {
	return "App Runner service with root-path health check"
}
func (apprunnerRootHealthCheck) Description() string {
	return "An App Runner service whose health_check path is \"/\" treats a " +
		"bare 200 from the web root as healthy, which can mask a broken " +
		"application behind a static page. Point the health check at a " +
		"dedicated readiness endpoint."
}
func (apprunnerRootHealthCheck) Severity() ir.Severity { return ir.SeverityLow }
func (apprunnerRootHealthCheck) AppliesTo(resType string) bool {
	return resType == "aws_apprunner_service"
}

func (s apprunnerRootHealthCheck) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "health_check")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	path, span, ppresent, pknown := blockString(blks[0], "path")
	if !ppresent || !pknown {
		return nil
	}
	if path != "/" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "health_check.path", span,
		"\"/\"", "health_check { path = \"/healthz\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-818: Batch job definition running privileged containers
// ---------------------------------------------------------------------------

type batchJobPrivileged struct{}

func (batchJobPrivileged) ID() string { return "AEGIS-AWS-818" }
func (batchJobPrivileged) Title() string {
	return "Batch job definition running privileged containers"
}
func (batchJobPrivileged) Description() string {
	return "A Batch job definition whose container_properties enables " +
		"privileged mode grants the job container full host access, letting " +
		"a compromised workload escape to the compute environment. Remove " +
		"privileged mode unless the job genuinely needs it."
}
func (batchJobPrivileged) Severity() ir.Severity { return ir.SeverityHigh }
func (batchJobPrivileged) AppliesTo(resType string) bool {
	return resType == "aws_batch_job_definition"
}

func (s batchJobPrivileged) Check(r ir.Resource) []ir.Finding {
	// container_properties is usually a JSON string; it may also arrive as
	// a block shape from some adapters. Check both, never flag on unknown.
	if blks, _, present, known := getBlocks(r, "container_properties"); present && known {
		for _, b := range blks {
			priv, _, ppresent, pknown := blockBool(b, "privileged")
			if ppresent && pknown && priv {
				return []ir.Finding{sdFinding(s, r,
					"container_properties.privileged", ir.Span{},
					"true", "privileged = false")}
			}
		}
	}
	doc, span, present, known := getString(r, "container_properties")
	if !present || !known {
		return nil
	}
	lowered := strings.ToLower(strings.ReplaceAll(doc, " ", ""))
	if strings.Contains(lowered, "\"privileged\":true") {
		return []ir.Finding{sdFinding(s, r, "container_properties", span,
			"privileged enabled", "container_properties without privileged mode")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-819: Glue security configuration without encryption
// ---------------------------------------------------------------------------

type glueNoSecurityConfig struct{}

func (glueNoSecurityConfig) ID() string { return "AEGIS-AWS-819" }
func (glueNoSecurityConfig) Title() string {
	return "Glue security configuration without encryption configuration"
}
func (glueNoSecurityConfig) Description() string {
	return "A Glue security configuration with no encryption_configuration " +
		"block leaves Glue data catalog, job bookmarks and S3 data encrypted " +
		"only with AWS-managed keys. Add encryption_configuration with " +
		"customer KMS keys for catalog, job and S3 encryption."
}
func (glueNoSecurityConfig) Severity() ir.Severity { return ir.SeverityMedium }
func (glueNoSecurityConfig) AppliesTo(resType string) bool {
	return resType == "aws_glue_security_configuration"
}

func (s glueNoSecurityConfig) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "encryption_configuration")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return absentInsecureDefault(s, r, "encryption_configuration",
		"absent (no Glue encryption configured)",
		"encryption_configuration { cloudwatch_encryption { ... } ... }")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-820: Athena workgroup without SSE-KMS query result encryption
// ---------------------------------------------------------------------------

type athenaWorkgroupNoKMS struct{}

func (athenaWorkgroupNoKMS) ID() string { return "AEGIS-AWS-820" }
func (athenaWorkgroupNoKMS) Title() string {
	return "Athena workgroup without SSE-KMS query result encryption"
}
func (athenaWorkgroupNoKMS) Description() string {
	return "An Athena workgroup whose result encryption_option is not " +
		"SSE_KMS (SSE_S3 or CSE_KMS are the common gaps) stores query results " +
		"in S3 without a customer managed key, forfeiting key-policy control " +
		"over potentially sensitive result sets. Use SSE_KMS with a customer " +
		"managed key."
}
func (athenaWorkgroupNoKMS) Severity() ir.Severity { return ir.SeverityHigh }
func (athenaWorkgroupNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_athena_workgroup"
}

func (s athenaWorkgroupNoKMS) Check(r ir.Resource) []ir.Finding {
	const attr = "configuration.result_configuration.encryption_configuration.encryption_option"
	cfg, _, present, known := getBlocks(r, "configuration")
	if present && !known {
		return nil
	}
	if !present || len(cfg) == 0 {
		return absentInsecureDefault(s, r, attr,
			"absent (provider default: SSE_S3)", "encryption_option = \"SSE_KMS\"")
	}
	rc := blockList(cfg[0], "result_configuration")
	if len(rc) == 0 {
		return absentInsecureDefault(s, r, attr,
			"absent (no result_configuration)", "encryption_option = \"SSE_KMS\"")
	}
	ec := blockList(rc[0], "encryption_configuration")
	if len(ec) == 0 {
		return absentInsecureDefault(s, r, attr,
			"absent (no encryption_configuration)", "encryption_option = \"SSE_KMS\"")
	}
	opt, span, opresent, oknown := blockString(ec[0], "encryption_option")
	if opresent && !oknown {
		return nil
	}
	if opresent && opt == "SSE_KMS" {
		return nil
	}
	if !opresent {
		return absentInsecureDefault(s, r, attr,
			"absent (provider default: SSE_S3)", "encryption_option = \"SSE_KMS\"")
	}
	return []ir.Finding{sdFinding(s, r, attr, span,
		"\""+opt+"\"", "encryption_option = \"SSE_KMS\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-821: Athena workgroup not enforcing workgroup configuration
// ---------------------------------------------------------------------------

type athenaNoEnforceWorkgroup struct{}

func (athenaNoEnforceWorkgroup) ID() string { return "AEGIS-AWS-821" }
func (athenaNoEnforceWorkgroup) Title() string {
	return "Athena workgroup not enforcing workgroup configuration"
}
func (athenaNoEnforceWorkgroup) Description() string {
	return "An Athena workgroup with enforce_workgroup_configuration = false " +
		"lets clients override the workgroup's output location and " +
		"encryption settings per query, bypassing the guarded result bucket. " +
		"Set enforce_workgroup_configuration = true."
}
func (athenaNoEnforceWorkgroup) Severity() ir.Severity { return ir.SeverityMedium }
func (athenaNoEnforceWorkgroup) AppliesTo(resType string) bool {
	return resType == "aws_athena_workgroup"
}

func (s athenaNoEnforceWorkgroup) Check(r ir.Resource) []ir.Finding {
	cfg, _, present, known := getBlocks(r, "configuration")
	if !present || !known || len(cfg) == 0 {
		return nil // provider default is true: absent is safe
	}
	enf, span, epresent, eknown := blockBool(cfg[0], "enforce_workgroup_configuration")
	if !epresent || !eknown {
		return nil
	}
	if enf {
		return nil
	}
	return []ir.Finding{sdFinding(s, r,
		"configuration.enforce_workgroup_configuration", span,
		"false", "enforce_workgroup_configuration = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-822: Kinesis stream without shard-level metrics
// ---------------------------------------------------------------------------
//
// (The stream-encryption check already exists as AEGIS-AWS-350; this rule
// covers the distinct observability gap instead of duplicating it.)

type kinesisNoShardMetrics struct{}

func (kinesisNoShardMetrics) ID() string { return "AEGIS-AWS-822" }
func (kinesisNoShardMetrics) Title() string {
	return "Kinesis stream without shard-level metrics"
}
func (kinesisNoShardMetrics) Description() string {
	return "A Kinesis stream with no shard_level_metrics configured emits " +
		"only aggregate stream metrics, hiding per-shard hot partitions and " +
		"anomalous throughput that signal abuse. Enable shard-level metrics " +
		"such as IncomingBytes and OutgoingRecords."
}
func (kinesisNoShardMetrics) Severity() ir.Severity { return ir.SeverityLow }
func (kinesisNoShardMetrics) AppliesTo(resType string) bool {
	return resType == "aws_kinesis_stream"
}

func (s kinesisNoShardMetrics) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["shard_level_metrics"]
	if !ok {
		return absentInsecureDefault(s, r, "shard_level_metrics",
			"absent (no shard-level metrics)",
			"shard_level_metrics = [\"IncomingBytes\", \"OutgoingRecords\"]")
	}
	if !v.Known {
		return nil
	}
	l, ok := v.AsList()
	if !ok {
		return nil // unexpected shape: undecidable
	}
	if len(l) == 0 {
		return []ir.Finding{sdFinding(s, r, "shard_level_metrics", v.Span,
			"[] (empty)",
			"shard_level_metrics = [\"IncomingBytes\", \"OutgoingRecords\"]")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-823: Firehose delivery stream without server-side encryption
// ---------------------------------------------------------------------------

type firehoseNoSSE struct{}

func (firehoseNoSSE) ID() string { return "AEGIS-AWS-823" }
func (firehoseNoSSE) Title() string {
	return "Firehose delivery stream without server-side encryption"
}
func (firehoseNoSSE) Description() string {
	return "A Firehose delivery stream with no server_side_encryption block " +
		"writes destination data without a customer managed key. Add " +
		"server_side_encryption with a customer KMS key."
}
func (firehoseNoSSE) Severity() ir.Severity { return ir.SeverityMedium }
func (firehoseNoSSE) AppliesTo(resType string) bool {
	return resType == "aws_kinesis_firehose_delivery_stream"
}

func (s firehoseNoSSE) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "server_side_encryption")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return absentInsecureDefault(s, r, "server_side_encryption",
		"absent (no Firehose SSE configured)",
		"server_side_encryption { enabled = true ... }")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-824: Timestream scheduled query error reports without SSE-KMS
// ---------------------------------------------------------------------------
//
// (The write-database kms_key_id check already exists as AEGIS-AWS-435;
// this rule covers the distinct scheduled-query error-report gap instead
// of duplicating it.)

type timestreamQueryReportNoKMS struct{}

func (timestreamQueryReportNoKMS) ID() string { return "AEGIS-AWS-824" }
func (timestreamQueryReportNoKMS) Title() string {
	return "Timestream scheduled query error reports without SSE-KMS"
}
func (timestreamQueryReportNoKMS) Description() string {
	return "A Timestream scheduled query whose error_report_configuration " +
		"s3_configuration does not use encryption_option = \"SSE_KMS\" " +
		"writes error reports (which can embed query fragments and data) to " +
		"S3 without a customer managed key. Use SSE_KMS."
}
func (timestreamQueryReportNoKMS) Severity() ir.Severity { return ir.SeverityMedium }
func (timestreamQueryReportNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_timestreamquery_scheduled_query"
}

func (s timestreamQueryReportNoKMS) Check(r ir.Resource) []ir.Finding {
	const attr = "error_report_configuration.s3_configuration.encryption_option"
	erc, _, present, known := getBlocks(r, "error_report_configuration")
	if !present || !known || len(erc) == 0 {
		return nil // no error reports configured: nothing to encrypt
	}
	s3c := blockList(erc[0], "s3_configuration")
	if len(s3c) == 0 {
		return nil
	}
	opt, span, opresent, oknown := blockString(s3c[0], "encryption_option")
	if opresent && !oknown {
		return nil
	}
	if opresent && opt == "SSE_KMS" {
		return nil
	}
	if !opresent {
		return absentInsecureDefault(s, r, attr,
			"absent (provider default: SSE_S3)", "encryption_option = \"SSE_KMS\"")
	}
	return []ir.Finding{sdFinding(s, r, attr, span,
		"\""+opt+"\"", "encryption_option = \"SSE_KMS\"")}
}
