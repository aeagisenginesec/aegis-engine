package gcp

import (
	"testing"

	"aegis/internal/ir"
)

func mustQuiet(t *testing.T, f []ir.Finding) {
	t.Helper()
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(f), f)
	}
}

func kn(n float64, line int) ir.Value { return ir.Value{Raw: n, Known: true, Span: spanAt(line)} }

// Pack registration: GCP5Rules must be wired into Rules() in ID order.
func TestGCP5RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	prev := idx["AEGIS-GCP-120"]
	for n := 123; n <= 142; n++ {
		id := "AEGIS-GCP-" + itoa(n)
		i, ok := idx[id]
		if !ok {
			t.Fatalf("rule %s not registered", id)
		}
		if i != prev+1 {
			t.Fatalf("rule %s out of order at %d, want %d", id, i, prev+1)
		}
		prev = i
	}
}

func itoa(n int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-123..125: Memorystore Redis
// ---------------------------------------------------------------------------

func TestGCP123_125(t *testing.T) {
	// 123: no AUTH
	mustFinding(t, runRule(redisNoAuth{}, res("google_redis_instance", "r", nil)), "AEGIS-GCP-123")
	mustFinding(t, runRule(redisNoAuth{}, res("google_redis_instance", "r",
		map[string]ir.Value{"auth_enabled": kv(false, 3)})), "AEGIS-GCP-123")
	mustQuiet(t, runRule(redisNoAuth{}, res("google_redis_instance", "r",
		map[string]ir.Value{"auth_enabled": kv(true, 3)})))
	mustQuiet(t, runRule(redisNoAuth{}, res("google_redis_instance", "r",
		map[string]ir.Value{"auth_enabled": ku(3)})))

	// 124: no TLS
	f := mustFinding(t, runRule(redisNoTLS{}, res("google_redis_instance", "r", nil)), "AEGIS-GCP-124")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("124: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(redisNoTLS{}, res("google_redis_instance", "r",
		map[string]ir.Value{"transit_encryption_mode": ks("SERVER_AUTHENTICATION", 3)})))

	// 125: no CMEK
	mustFinding(t, runRule(redisNoCMEK{}, res("google_redis_instance", "r", nil)), "AEGIS-GCP-125")
	mustQuiet(t, runRule(redisNoCMEK{}, res("google_redis_instance", "r",
		map[string]ir.Value{"kms_key_name": ks("projects/p/locations/l/keyRings/k/cryptoKeys/k", 3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-126: Spanner database without CMEK
// ---------------------------------------------------------------------------

func TestGCP126(t *testing.T) {
	mustFinding(t, runRule(spannerDBNoCMEK{}, res("google_spanner_database", "d", nil)), "AEGIS-GCP-126")
	r := res("google_spanner_database", "d", map[string]ir.Value{
		"encryption_config": blks(3, blk("kms_key_name", ks("k", 4))),
	})
	mustQuiet(t, runRule(spannerDBNoCMEK{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-127/128: Artifact Registry
// ---------------------------------------------------------------------------

func TestGCP127_128(t *testing.T) {
	mustFinding(t, runRule(artifactNoCMEK{}, res("google_artifact_registry_repository", "a", nil)), "AEGIS-GCP-127")
	mustFinding(t, runRule(artifactNoCleanup{}, res("google_artifact_registry_repository", "a", nil)), "AEGIS-GCP-128")
	r := res("google_artifact_registry_repository", "a", map[string]ir.Value{
		"kms_key_name":     ks("k", 3),
		"cleanup_policies": blks(4, blk("id", ks("keep", 5))),
	})
	mustQuiet(t, runRule(artifactNoCMEK{}, r))
	mustQuiet(t, runRule(artifactNoCleanup{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-129/130: Cloud Run v2
// ---------------------------------------------------------------------------

func TestGCP129_130(t *testing.T) {
	mustFinding(t, runRule(cloudRunNoDelProtect{}, res("google_cloud_run_v2_service", "s", nil)), "AEGIS-GCP-129")
	mustQuiet(t, runRule(cloudRunNoDelProtect{}, res("google_cloud_run_v2_service", "s",
		map[string]ir.Value{"deletion_protection": kv(true, 3)})))

	mustFinding(t, runRule(cloudRunIngressAll{}, res("google_cloud_run_v2_service", "s",
		map[string]ir.Value{"ingress": ks("INGRESS_TRAFFIC_ALL", 3)})), "AEGIS-GCP-130")
	mustQuiet(t, runRule(cloudRunIngressAll{}, res("google_cloud_run_v2_service", "s",
		map[string]ir.Value{"ingress": ks("INGRESS_TRAFFIC_INTERNAL_ONLY", 3)})))
	mustQuiet(t, runRule(cloudRunIngressAll{}, res("google_cloud_run_v2_service", "s", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-131: Cloud Build trigger with default service account
// ---------------------------------------------------------------------------

func TestGCP131(t *testing.T) {
	mustFinding(t, runRule(cloudBuildDefaultSA{}, res("google_cloudbuild_trigger", "t", nil)), "AEGIS-GCP-131")
	mustQuiet(t, runRule(cloudBuildDefaultSA{}, res("google_cloudbuild_trigger", "t",
		map[string]ir.Value{"service_account": ks("projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com", 3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-132/133/134: Dataflow / Dataproc / Composer CMEK
// ---------------------------------------------------------------------------

func TestGCP132_134(t *testing.T) {
	mustFinding(t, runRule(dataflowNoCMEK{}, res("google_dataflow_job", "j", nil)), "AEGIS-GCP-132")
	mustQuiet(t, runRule(dataflowNoCMEK{}, res("google_dataflow_job", "j",
		map[string]ir.Value{"kms_key_name": ks("k", 3)})))

	mustFinding(t, runRule(dataprocNoCMEK{}, res("google_dataproc_cluster", "c", nil)), "AEGIS-GCP-133")
	mustQuiet(t, runRule(dataprocNoCMEK{}, res("google_dataproc_cluster", "c", map[string]ir.Value{
		"cluster_config": blks(3, blk("encryption_config",
			blks(4, blk("kms_key_name", ks("k", 5))))),
	})))

	mustFinding(t, runRule(composerNoCMEK{}, res("google_composer_environment", "e", nil)), "AEGIS-GCP-134")
	mustQuiet(t, runRule(composerNoCMEK{}, res("google_composer_environment", "e", map[string]ir.Value{
		"config": blks(3, blk("encryption_config",
			blks(4, blk("kms_key_name", ks("k", 5))))),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-135: Cloud Scheduler HTTP target without authentication
// ---------------------------------------------------------------------------

func TestGCP135(t *testing.T) {
	mustFinding(t, runRule(schedulerNoAuth{}, res("google_cloud_scheduler_job", "j", map[string]ir.Value{
		"http_target": blks(3, blk("uri", ks("https://example.com/hook", 4))),
	})), "AEGIS-GCP-135")
	mustQuiet(t, runRule(schedulerNoAuth{}, res("google_cloud_scheduler_job", "j", map[string]ir.Value{
		"http_target": blks(3, blk("uri", ks("https://example.com/hook", 4),
			"oidc_token", blks(5, blk("service_account_email", ks("sa@x.iam.gserviceaccount.com", 6))))),
	})))
	mustQuiet(t, runRule(schedulerNoAuth{}, res("google_cloud_scheduler_job", "j", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-136: SSL policy below TLS 1.2
// ---------------------------------------------------------------------------

func TestGCP136(t *testing.T) {
	f := mustFinding(t, runRule(sslPolicyWeakTLS{}, res("google_compute_ssl_policy", "p",
		map[string]ir.Value{"min_tls_version": ks("TLS_1_0", 3)})), "AEGIS-GCP-136")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustFinding(t, runRule(sslPolicyWeakTLS{}, res("google_compute_ssl_policy", "p",
		map[string]ir.Value{"min_tls_version": ks("TLS_1_1", 3)})), "AEGIS-GCP-136")
	mustQuiet(t, runRule(sslPolicyWeakTLS{}, res("google_compute_ssl_policy", "p",
		map[string]ir.Value{"min_tls_version": ks("TLS_1_2", 3)})))
	mustQuiet(t, runRule(sslPolicyWeakTLS{}, res("google_compute_ssl_policy", "p", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-137: Backend service without logging
// ---------------------------------------------------------------------------

func TestGCP137(t *testing.T) {
	mustFinding(t, runRule(backendNoLogging{}, res("google_compute_backend_service", "b", nil)), "AEGIS-GCP-137")
	mustQuiet(t, runRule(backendNoLogging{}, res("google_compute_backend_service", "b", map[string]ir.Value{
		"log_config": blks(3, blk("enable", kv(true, 4))),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-138: Secret Manager user-managed replication without CMEK
// ---------------------------------------------------------------------------

func TestGCP138(t *testing.T) {
	mustFinding(t, runRule(secretNoCMEK{}, res("google_secret_manager_secret", "s", map[string]ir.Value{
		"replication": blks(3, blk("user_managed",
			blks(4, blk("replicas",
				blks(5, blk("location", ks("us-central1", 6))))))),
	})), "AEGIS-GCP-138")
	mustQuiet(t, runRule(secretNoCMEK{}, res("google_secret_manager_secret", "s", map[string]ir.Value{
		"replication": blks(3, blk("user_managed",
			blks(4, blk("replicas",
				blks(5, blk("location", ks("us-central1", 6),
					"customer_managed_encryption", blks(7, blk("kms_key_name", ks("k", 8))))))))),
	})))
	mustQuiet(t, runRule(secretNoCMEK{}, res("google_secret_manager_secret", "s", map[string]ir.Value{
		"replication": blks(3, blk("automatic", kv(true, 4))),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-139/140/141/142
// ---------------------------------------------------------------------------

func TestGCP139_142(t *testing.T) {
	// 139: sink disabled
	mustFinding(t, runRule(logSinkDisabled{}, res("google_logging_project_sink", "s",
		map[string]ir.Value{"disabled": kv(true, 3)})), "AEGIS-GCP-139")
	mustQuiet(t, runRule(logSinkDisabled{}, res("google_logging_project_sink", "s", nil)))

	// 140: filestore no CMEK
	mustFinding(t, runRule(filestoreNoCMEK{}, res("google_filestore_instance", "f", nil)), "AEGIS-GCP-140")
	mustQuiet(t, runRule(filestoreNoCMEK{}, res("google_filestore_instance", "f",
		map[string]ir.Value{"kms_key_name": ks("k", 3)})))

	// 141: alert policy disabled
	mustFinding(t, runRule(alertPolicyDisabled{}, res("google_monitoring_alert_policy", "a",
		map[string]ir.Value{"enabled": kv(false, 3)})), "AEGIS-GCP-141")
	mustQuiet(t, runRule(alertPolicyDisabled{}, res("google_monitoring_alert_policy", "a", nil)))

	// 142: IKEv1
	f := mustFinding(t, runRule(vpnIKEv1{}, res("google_compute_vpn_tunnel", "v",
		map[string]ir.Value{"ike_version": kn(1, 3)})), "AEGIS-GCP-142")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(vpnIKEv1{}, res("google_compute_vpn_tunnel", "v",
		map[string]ir.Value{"ike_version": kn(2, 3)})))
	mustQuiet(t, runRule(vpnIKEv1{}, res("google_compute_vpn_tunnel", "v", nil)))
}
