// Package gcp — expansion round 5 (AEGIS-GCP-123..142).
//
// Fills thin areas: Memorystore Redis, Spanner, Artifact Registry, Cloud
// Run v2, Cloud Functions v2, Dataflow, Dataproc, Composer, Cloud
// Scheduler, SSL policies, backend-service logging, Secret Manager
// replication, log sinks, Filestore, monitoring alert policies, and VPN.
//
// Absent-attribute policy for this file: an absent attribute yields a
// finding when the provider default is the insecure one (Redis AUTH/TLS
// off, no CMEK where the provider accepts kms_key_name, no cleanup
// policies, no deletion protection, log sink enabled by default so only
// explicit disabled fires). Present-but-unresolved values yield NO finding.
package gcp

import (
	"strings"

	"aegis/internal/ir"
)

// GCP5Rules returns GCP expansion rules 123..142 in ID order.
func GCP5Rules() []ir.Rule {
	return []ir.Rule{
		redisNoAuth{},          // AEGIS-GCP-123
		redisNoTLS{},           // AEGIS-GCP-124
		redisNoCMEK{},          // AEGIS-GCP-125
		spannerDBNoCMEK{},      // AEGIS-GCP-126
		artifactNoCMEK{},       // AEGIS-GCP-127
		artifactNoCleanup{},    // AEGIS-GCP-128
		cloudRunNoDelProtect{}, // AEGIS-GCP-129
		cloudRunIngressAll{},   // AEGIS-GCP-130
		cloudBuildDefaultSA{},  // AEGIS-GCP-131
		dataflowNoCMEK{},       // AEGIS-GCP-132
		dataprocNoCMEK{},       // AEGIS-GCP-133
		composerNoCMEK{},       // AEGIS-GCP-134
		schedulerNoAuth{},      // AEGIS-GCP-135
		sslPolicyWeakTLS{},     // AEGIS-GCP-136
		backendNoLogging{},     // AEGIS-GCP-137
		secretNoCMEK{},         // AEGIS-GCP-138
		logSinkDisabled{},      // AEGIS-GCP-139
		filestoreNoCMEK{},      // AEGIS-GCP-140
		alertPolicyDisabled{},  // AEGIS-GCP-141
		vpnIKEv1{},             // AEGIS-GCP-142
	}
}

// noCMEK is a shared check: fires when neither kms_key_name nor kms_key_id
// is set (the provider names the attribute differently per resource).
func noCMEK(rule ir.Rule, r ir.Resource) []ir.Finding {
	for _, attr := range []string{"kms_key_name", "kms_key_id"} {
		key, _, present, known := getString(r, attr)
		if present && !known {
			return nil // unresolved: cannot decide
		}
		if present && strings.TrimSpace(key) != "" {
			return nil
		}
	}
	return []ir.Finding{mkFinding(rule, r, "kms_key_name",
		evidenceSpan(ir.Span{}, r.Span), "absent (Google-managed keys)",
		"kms_key_name = \"<kms-key>\"")}
}

// nestedCMEK fires when path[0].path[1]...path[n] (nested blocks) does not
// carry a non-empty kms_key_name/kms_key_id leaf.
func nestedCMEK(rule ir.Rule, r ir.Resource, path []string, leaf string, attr string) []ir.Finding {
	blks, span, present, known := getBlocks(r, path[0])
	if present && !known {
		return nil
	}
	if present {
		cur := blks
		ok := true
		for _, p := range path[1:] {
			var next []map[string]ir.Value
			for _, b := range cur {
				next = append(next, blockList(b, p)...)
			}
			if len(next) == 0 {
				ok = false
				break
			}
			cur = next
		}
		if ok {
			for _, b := range cur {
				if key, _, _, kok := blockString(b, leaf); kok && strings.TrimSpace(key) != "" {
					return nil
				}
			}
		}
	}
	return []ir.Finding{mkFinding(rule, r, attr,
		evidenceSpan(span, r.Span),
		"absent (Google-managed keys)",
		strings.Join(path, ".")+"."+leaf+" = \"<kms-key>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-123: Memorystore Redis without AUTH
// ---------------------------------------------------------------------------

type redisNoAuth struct{}

func (redisNoAuth) ID() string { return "AEGIS-GCP-123" }
func (redisNoAuth) Title() string {
	return "Memorystore Redis without AUTH enabled"
}
func (redisNoAuth) Description() string {
	return "google_redis_instance without auth_enabled = true accepts " +
		"unauthenticated connections to the Redis instance. Enable AUTH " +
		"so clients must present the instance password."
}
func (redisNoAuth) Severity() ir.Severity { return ir.SeverityHigh }

func (redisNoAuth) AppliesTo(resType string) bool {
	return resType == "google_redis_instance"
}

func (s redisNoAuth) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "auth_enabled")
	if present && !known {
		return nil
	}
	if present && en {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(s, r, "auth_enabled",
		evidenceSpan(span, r.Span), actual, "auth_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-124: Memorystore Redis without TLS
// ---------------------------------------------------------------------------

type redisNoTLS struct{}

func (redisNoTLS) ID() string { return "AEGIS-GCP-124" }
func (redisNoTLS) Title() string {
	return "Memorystore Redis without in-transit encryption"
}
func (redisNoTLS) Description() string {
	return "google_redis_instance without transit_encryption_mode = " +
		"\"SERVER_AUTHENTICATION\" sends Redis traffic unencrypted, " +
		"exposing credentials and data to network sniffing. Enable " +
		"server-authenticated TLS."
}
func (redisNoTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (redisNoTLS) AppliesTo(resType string) bool {
	return resType == "google_redis_instance"
}

func (s redisNoTLS) Check(r ir.Resource) []ir.Finding {
	mode, span, present, known := getString(r, "transit_encryption_mode")
	if present && !known {
		return nil
	}
	if present && strings.EqualFold(strings.TrimSpace(mode), "SERVER_AUTHENTICATION") {
		return nil
	}
	actual := "absent (provider default: DISABLED)"
	if present {
		actual = mode
	}
	return []ir.Finding{mkFinding(s, r, "transit_encryption_mode",
		evidenceSpan(span, r.Span), actual,
		"transit_encryption_mode = \"SERVER_AUTHENTICATION\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-125: Memorystore Redis without CMEK
// ---------------------------------------------------------------------------

type redisNoCMEK struct{}

func (redisNoCMEK) ID() string { return "AEGIS-GCP-125" }
func (redisNoCMEK) Title() string {
	return "Memorystore Redis without customer-managed encryption"
}
func (redisNoCMEK) Description() string {
	return "google_redis_instance without kms_key_name relies on " +
		"Google-managed keys. Assign a customer-managed Cloud KMS key for " +
		"control over rotation and revocation."
}
func (redisNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (redisNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_redis_instance"
}

func (s redisNoCMEK) Check(r ir.Resource) []ir.Finding {
	return noCMEK(s, r)
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-126: Spanner database without CMEK
// ---------------------------------------------------------------------------

type spannerDBNoCMEK struct{}

func (spannerDBNoCMEK) ID() string { return "AEGIS-GCP-126" }
func (spannerDBNoCMEK) Title() string {
	return "Spanner database without customer-managed encryption"
}
func (spannerDBNoCMEK) Description() string {
	return "google_spanner_database without encryption_config.kms_key_name " +
		"relies on Google-managed keys. Assign a customer-managed Cloud " +
		"KMS key."
}
func (spannerDBNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (spannerDBNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_spanner_database"
}

func (s spannerDBNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"encryption_config"}, "kms_key_name", "encryption_config")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-127: Artifact Registry repository without CMEK
// ---------------------------------------------------------------------------

type artifactNoCMEK struct{}

func (artifactNoCMEK) ID() string { return "AEGIS-GCP-127" }
func (artifactNoCMEK) Title() string {
	return "Artifact Registry repository without customer-managed encryption"
}
func (artifactNoCMEK) Description() string {
	return "google_artifact_registry_repository without kms_key_name " +
		"relies on Google-managed keys for stored artifacts. Assign a " +
		"customer-managed Cloud KMS key."
}
func (artifactNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (artifactNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_artifact_registry_repository"
}

func (s artifactNoCMEK) Check(r ir.Resource) []ir.Finding {
	return noCMEK(s, r)
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-128: Artifact Registry repository without cleanup policies
// ---------------------------------------------------------------------------

type artifactNoCleanup struct{}

func (artifactNoCleanup) ID() string { return "AEGIS-GCP-128" }
func (artifactNoCleanup) Title() string {
	return "Artifact Registry repository without cleanup policies"
}
func (artifactNoCleanup) Description() string {
	return "google_artifact_registry_repository without cleanup_policies " +
		"accumulates stale and vulnerable image versions indefinitely. " +
		"Define cleanup policies to prune old artifacts."
}
func (artifactNoCleanup) Severity() ir.Severity { return ir.SeverityLow }

func (artifactNoCleanup) AppliesTo(resType string) bool {
	return resType == "google_artifact_registry_repository"
}

func (s artifactNoCleanup) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "cleanup_policies")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "cleanup_policies",
		evidenceSpan(span, r.Span), "absent (no cleanup)",
		"cleanup_policies { ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-129: Cloud Run v2 service without deletion protection
// ---------------------------------------------------------------------------

type cloudRunNoDelProtect struct{}

func (cloudRunNoDelProtect) ID() string { return "AEGIS-GCP-129" }
func (cloudRunNoDelProtect) Title() string {
	return "Cloud Run v2 service without deletion protection"
}
func (cloudRunNoDelProtect) Description() string {
	return "google_cloud_run_v2_service without deletion_protection = true " +
		"can be destroyed by an errant apply or compromised credential. " +
		"Enable deletion protection for production services."
}
func (cloudRunNoDelProtect) Severity() ir.Severity { return ir.SeverityLow }

func (cloudRunNoDelProtect) AppliesTo(resType string) bool {
	return resType == "google_cloud_run_v2_service"
}

func (s cloudRunNoDelProtect) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "deletion_protection")
	if present && !known {
		return nil
	}
	if present && en {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(s, r, "deletion_protection",
		evidenceSpan(span, r.Span), actual, "deletion_protection = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-130: Cloud Run v2 service with public ingress
// ---------------------------------------------------------------------------

type cloudRunIngressAll struct{}

func (cloudRunIngressAll) ID() string { return "AEGIS-GCP-130" }
func (cloudRunIngressAll) Title() string {
	return "Cloud Run v2 service with internet ingress"
}
func (cloudRunIngressAll) Description() string {
	return "google_cloud_run_v2_service with ingress = " +
		"\"INGRESS_TRAFFIC_ALL\" accepts requests directly from the " +
		"internet. Restrict ingress to internal traffic or a load balancer " +
		"when the service is not meant to be public."
}
func (cloudRunIngressAll) Severity() ir.Severity { return ir.SeverityMedium }

func (cloudRunIngressAll) AppliesTo(resType string) bool {
	return resType == "google_cloud_run_v2_service"
}

func (s cloudRunIngressAll) Check(r ir.Resource) []ir.Finding {
	ing, span, present, known := getString(r, "ingress")
	if !present || !known {
		return nil // default is INGRESS_TRAFFIC_ALL, but IAM decides; only explicit
	}
	if strings.EqualFold(strings.TrimSpace(ing), "INGRESS_TRAFFIC_ALL") {
		return []ir.Finding{mkFinding(s, r, "ingress", span, ing,
			"ingress = \"INGRESS_TRAFFIC_INTERNAL_ONLY\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-131: Cloud Build trigger with default service account
// ---------------------------------------------------------------------------

type cloudBuildDefaultSA struct{}

func (cloudBuildDefaultSA) ID() string { return "AEGIS-GCP-131" }
func (cloudBuildDefaultSA) Title() string {
	return "Cloud Build trigger with default service account"
}
func (cloudBuildDefaultSA) Description() string {
	return "google_cloudbuild_trigger without an explicit service_account " +
		"runs builds as the default Cloud Build service account, which " +
		"carries broad project permissions. Pin a least-privilege service " +
		"account to each trigger."
}
func (cloudBuildDefaultSA) Severity() ir.Severity { return ir.SeverityMedium }

func (cloudBuildDefaultSA) AppliesTo(resType string) bool {
	return resType == "google_cloudbuild_trigger"
}

func (s cloudBuildDefaultSA) Check(r ir.Resource) []ir.Finding {
	sa, span, present, known := getString(r, "service_account")
	if present && !known {
		return nil
	}
	if present && strings.TrimSpace(sa) != "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "service_account",
		evidenceSpan(span, r.Span), "absent (default Cloud Build SA)",
		"service_account = \"projects/<p>/serviceAccounts/<sa>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-132: Dataflow job without CMEK
// ---------------------------------------------------------------------------

type dataflowNoCMEK struct{}

func (dataflowNoCMEK) ID() string { return "AEGIS-GCP-132" }
func (dataflowNoCMEK) Title() string {
	return "Dataflow job without customer-managed encryption"
}
func (dataflowNoCMEK) Description() string {
	return "google_dataflow_job without kms_key_name relies on " +
		"Google-managed keys for pipeline state and shuffled data. Assign " +
		"a customer-managed Cloud KMS key."
}
func (dataflowNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (dataflowNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_dataflow_job"
}

func (s dataflowNoCMEK) Check(r ir.Resource) []ir.Finding {
	return noCMEK(s, r)
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-133: Dataproc cluster without CMEK
// ---------------------------------------------------------------------------

type dataprocNoCMEK struct{}

func (dataprocNoCMEK) ID() string { return "AEGIS-GCP-133" }
func (dataprocNoCMEK) Title() string {
	return "Dataproc cluster without customer-managed encryption"
}
func (dataprocNoCMEK) Description() string {
	return "google_dataproc_cluster without " +
		"cluster_config.encryption_config.kms_key_name relies on " +
		"Google-managed keys for cluster disks. Assign a customer-managed " +
		"Cloud KMS key."
}
func (dataprocNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (dataprocNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_dataproc_cluster"
}

func (s dataprocNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"cluster_config", "encryption_config"}, "kms_key_name", "cluster_config")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-134: Composer environment without CMEK
// ---------------------------------------------------------------------------

type composerNoCMEK struct{}

func (composerNoCMEK) ID() string { return "AEGIS-GCP-134" }
func (composerNoCMEK) Title() string {
	return "Composer environment without customer-managed encryption"
}
func (composerNoCMEK) Description() string {
	return "google_composer_environment without " +
		"config.encryption_config.kms_key_name relies on Google-managed " +
		"keys for the environment. Assign a customer-managed Cloud KMS key."
}
func (composerNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (composerNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_composer_environment"
}

func (s composerNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"config", "encryption_config"}, "kms_key_name", "config")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-135: Cloud Scheduler HTTP target without authentication
// ---------------------------------------------------------------------------

type schedulerNoAuth struct{}

func (schedulerNoAuth) ID() string { return "AEGIS-GCP-135" }
func (schedulerNoAuth) Title() string {
	return "Cloud Scheduler HTTP target without authentication"
}
func (schedulerNoAuth) Description() string {
	return "google_cloud_scheduler_job with an http_target block but no " +
		"oidc_token or oauth_token invokes the target without " +
		"authentication, letting anyone who discovers the URL trigger it. " +
		"Attach an OIDC or OAuth token."
}
func (schedulerNoAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (schedulerNoAuth) AppliesTo(resType string) bool {
	return resType == "google_cloud_scheduler_job"
}

func (s schedulerNoAuth) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "http_target")
	if !present || !known {
		return nil // no HTTP target: nothing to check
	}
	for _, b := range blks {
		if hasNonEmptyBlock(b, "oidc_token") || hasNonEmptyBlock(b, "oauth_token") {
			continue
		}
		return []ir.Finding{mkFinding(s, r, "http_target",
			evidenceSpan(span, r.Span), "http_target without oidc_token/oauth_token",
			"http_target { oidc_token { service_account_email = \"...\" } }")}
	}
	return nil
}

// hasNonEmptyBlock reports whether a block map carries a non-empty nested
// block under name.
func hasNonEmptyBlock(m map[string]ir.Value, name string) bool {
	v, ok := m[name]
	if !ok || !v.Known {
		return false
	}
	if _, ok := v.AsMap(); ok {
		return true
	}
	l, ok := v.AsList()
	return ok && len(l) > 0
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-136: SSL policy below TLS 1.2
// ---------------------------------------------------------------------------

type sslPolicyWeakTLS struct{}

func (sslPolicyWeakTLS) ID() string { return "AEGIS-GCP-136" }
func (sslPolicyWeakTLS) Title() string {
	return "SSL policy below TLS 1.2"
}
func (sslPolicyWeakTLS) Description() string {
	return "google_compute_ssl_policy with min_tls_version below TLS 1.2 " +
		"permits obsolete protocol versions with known weaknesses. Set " +
		"min_tls_version to TLS_1_2 or higher."
}
func (sslPolicyWeakTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (sslPolicyWeakTLS) AppliesTo(resType string) bool {
	return resType == "google_compute_ssl_policy"
}

func (s sslPolicyWeakTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "min_tls_version")
	if !present || !known {
		return nil
	}
	v := strings.ToUpper(strings.TrimSpace(ver))
	if v == "TLS_1_0" || v == "TLS_1_1" || v == "1.0" || v == "1.1" {
		return []ir.Finding{mkFinding(s, r, "min_tls_version", span, ver,
			"min_tls_version = \"TLS_1_2\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-137: Backend service without logging
// ---------------------------------------------------------------------------

type backendNoLogging struct{}

func (backendNoLogging) ID() string { return "AEGIS-GCP-137" }
func (backendNoLogging) Title() string {
	return "Backend service without logging"
}
func (backendNoLogging) Description() string {
	return "google_compute_backend_service without log_config.enable = " +
		"true produces no request logs, leaving load-balancer traffic " +
		"unaudited. Enable logging on the backend service."
}
func (backendNoLogging) Severity() ir.Severity { return ir.SeverityMedium }

func (backendNoLogging) AppliesTo(resType string) bool {
	return resType == "google_compute_backend_service"
}

func (s backendNoLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "log_config")
	if present && !known {
		return nil
	}
	if present {
		for _, b := range blks {
			if en, _, _, kok := blockBool(b, "enable"); kok && en {
				return nil
			}
		}
	}
	actual := "absent (logging disabled)"
	if present {
		actual = "log_config without enable = true"
	}
	return []ir.Finding{mkFinding(s, r, "log_config",
		evidenceSpan(span, r.Span), actual,
		"log_config { enable = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-138: Secret Manager user-managed replication without CMEK
// ---------------------------------------------------------------------------

type secretNoCMEK struct{}

func (secretNoCMEK) ID() string { return "AEGIS-GCP-138" }
func (secretNoCMEK) Title() string {
	return "Secret Manager user-managed replication without CMEK"
}
func (secretNoCMEK) Description() string {
	return "google_secret_manager_secret with user_managed replication but " +
		"no customer_managed_encryption.kms_key_name on a replica relies " +
		"on Google-managed keys. Assign a customer-managed Cloud KMS key " +
		"per replica."
}
func (secretNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (secretNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_secret_manager_secret"
}

func (s secretNoCMEK) Check(r ir.Resource) []ir.Finding {
	rep, span, present, known := getBlocks(r, "replication")
	if !present || !known {
		return nil
	}
	for _, rb := range rep {
		um := blockList(rb, "user_managed")
		if len(um) == 0 {
			continue // automatic replication: out of scope
		}
		for _, u := range um {
			for _, replica := range blockList(u, "replicas") {
				cmek := blockList(replica, "customer_managed_encryption")
				hasKey := false
				for _, c := range cmek {
					if key, _, _, kok := blockString(c, "kms_key_name"); kok && strings.TrimSpace(key) != "" {
						hasKey = true
					}
				}
				if !hasKey {
					return []ir.Finding{mkFinding(s, r, "replication",
						evidenceSpan(span, r.Span),
						"user_managed replica without customer_managed_encryption",
						"replicas { customer_managed_encryption { kms_key_name = \"...\" } }")}
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-139: Logging sink disabled
// ---------------------------------------------------------------------------

type logSinkDisabled struct{}

func (logSinkDisabled) ID() string { return "AEGIS-GCP-139" }
func (logSinkDisabled) Title() string {
	return "Logging sink disabled"
}
func (logSinkDisabled) Description() string {
	return "google_logging_project_sink with disabled = true stops the " +
		"export of audit logs to the sink destination, silently dropping " +
		"the audit trail. Keep sinks enabled."
}
func (logSinkDisabled) Severity() ir.Severity { return ir.SeverityMedium }

func (logSinkDisabled) AppliesTo(resType string) bool {
	return resType == "google_logging_project_sink"
}

func (s logSinkDisabled) Check(r ir.Resource) []ir.Finding {
	dis, span, present, known := getBool(r, "disabled")
	if !present || !known {
		return nil // default is enabled
	}
	if !dis {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "disabled", span, "true",
		"disabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-140: Filestore instance without CMEK
// ---------------------------------------------------------------------------

type filestoreNoCMEK struct{}

func (filestoreNoCMEK) ID() string { return "AEGIS-GCP-140" }
func (filestoreNoCMEK) Title() string {
	return "Filestore instance without customer-managed encryption"
}
func (filestoreNoCMEK) Description() string {
	return "google_filestore_instance without kms_key_name relies on " +
		"Google-managed keys for file shares. Assign a customer-managed " +
		"Cloud KMS key."
}
func (filestoreNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (filestoreNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_filestore_instance"
}

func (s filestoreNoCMEK) Check(r ir.Resource) []ir.Finding {
	return noCMEK(s, r)
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-141: Monitoring alert policy disabled
// ---------------------------------------------------------------------------

type alertPolicyDisabled struct{}

func (alertPolicyDisabled) ID() string { return "AEGIS-GCP-141" }
func (alertPolicyDisabled) Title() string {
	return "Monitoring alert policy disabled"
}
func (alertPolicyDisabled) Description() string {
	return "google_monitoring_alert_policy with enabled = false never " +
		"fires, so the condition it watches goes unmonitored. Keep alert " +
		"policies enabled or remove them."
}
func (alertPolicyDisabled) Severity() ir.Severity { return ir.SeverityLow }

func (alertPolicyDisabled) AppliesTo(resType string) bool {
	return resType == "google_monitoring_alert_policy"
}

func (s alertPolicyDisabled) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "enabled")
	if !present || !known {
		return nil // default is enabled
	}
	if en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "enabled", span, "false",
		"enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-142: VPN tunnel using IKEv1
// ---------------------------------------------------------------------------

type vpnIKEv1 struct{}

func (vpnIKEv1) ID() string { return "AEGIS-GCP-142" }
func (vpnIKEv1) Title() string {
	return "VPN tunnel using IKEv1"
}
func (vpnIKEv1) Description() string {
	return "google_compute_vpn_tunnel with ike_version = 1 uses the older " +
		"IKEv1 key exchange with known weaknesses. Use ike_version = 2."
}
func (vpnIKEv1) Severity() ir.Severity { return ir.SeverityHigh }

func (vpnIKEv1) AppliesTo(resType string) bool {
	return resType == "google_compute_vpn_tunnel"
}

func (s vpnIKEv1) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getNum(r, "ike_version")
	if !present || !known {
		return nil // default is IKEv2
	}
	if v == 1 {
		return []ir.Finding{mkFinding(s, r, "ike_version", span, "1",
			"ike_version = 2")}
	}
	return nil
}

// getNum classifies a numeric attribute into a tri-state.
func getNum(r ir.Resource, name string) (val float64, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return 0, ir.Span{}, false, false
	}
	if !v.Known {
		return 0, v.Span, true, false
	}
	f, ok := v.Raw.(float64)
	return f, v.Span, true, ok
}
