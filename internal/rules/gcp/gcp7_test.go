package gcp

import (
	"testing"

	"aegis/internal/ir"
)

// Pack registration: GCP7Rules must return 39 rules in ID order
// (195 removed as a strict subset of existing AEGIS-GCP-006).
// (Wiring GCP7Rules into Rules() in gcp.go is a separate step; this test
// validates the pack itself.)
func TestGCP7RegisteredInIDOrder(t *testing.T) {
	rules := GCP7Rules()
	wantIDs := []string{}
	for n := 183; n <= 222; n++ {
		if n == 195 {
			continue
		}
		wantIDs = append(wantIDs, "AEGIS-GCP-"+itoa(n))
	}
	if len(rules) != len(wantIDs) {
		t.Fatalf("expected %d rules, got %d", len(wantIDs), len(rules))
	}
	for i, r := range rules {
		if r.ID() != wantIDs[i] {
			t.Fatalf("rule %d: want %s, got %s", i, wantIDs[i], r.ID())
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-183/184: GCS bucket soft delete / versioning lifecycle
// ---------------------------------------------------------------------------

func TestGCP183_184(t *testing.T) {
	// 183: no soft-delete policy
	mustFinding(t, runRule(bucketNoSoftDelete{}, res("google_storage_bucket", "b", nil)), "AEGIS-GCP-183")
	mustQuiet(t, runRule(bucketNoSoftDelete{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"soft_delete_policy": blks(3, blk("retention_duration_seconds", kn(604800, 4))),
	})))
	mustQuiet(t, runRule(bucketNoSoftDelete{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"soft_delete_policy": ku(3),
	})))

	// 184: versioning without lifecycle
	mustFinding(t, runRule(bucketVersioningNoLife{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"versioning": blks(3, blk("enabled", kv(true, 4))),
	})), "AEGIS-GCP-184")
	mustQuiet(t, runRule(bucketVersioningNoLife{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"versioning":     blks(3, blk("enabled", kv(true, 4))),
		"lifecycle_rule": blks(5, blk("action", blks(6, blk("type", ks("Delete", 7))))),
	})))
	mustQuiet(t, runRule(bucketVersioningNoLife{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"versioning": blks(3, blk("enabled", kv(false, 4))),
	})))
	mustQuiet(t, runRule(bucketVersioningNoLife{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"versioning": ku(3),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-185/186: GCS IAM policy / default object ACL public
// ---------------------------------------------------------------------------

func TestGCP185_186(t *testing.T) {
	// 185: authoritative IAM policy with public binding
	f := mustFinding(t, runRule(bucketIAMPolicyPublic{}, res("google_storage_bucket_iam_policy", "p", map[string]ir.Value{
		"bindings": blks(3, blk("role", ks("roles/storage.objectViewer", 4),
			"members", strList(5, "allUsers"))),
	})), "AEGIS-GCP-185")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("185: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(bucketIAMPolicyPublic{}, res("google_storage_bucket_iam_policy", "p", map[string]ir.Value{
		"bindings": blks(3, blk("role", ks("roles/storage.objectViewer", 4),
			"members", strList(5, "group:eng@example.com"))),
	})))
	mustQuiet(t, runRule(bucketIAMPolicyPublic{}, res("google_storage_bucket_iam_policy", "p", map[string]ir.Value{
		"bindings": blks(3, blk("role", ku(4),
			"members", strList(5, "allUsers"))),
	})))

	// 186: default object ACL public
	mustFinding(t, runRule(bucketDefObjACLPublic{}, res("google_storage_default_object_access_control", "a", map[string]ir.Value{
		"entity": ks("allUsers", 3),
		"role":   ks("READER", 4),
	})), "AEGIS-GCP-186")
	mustFinding(t, runRule(bucketDefObjACLPublic{}, res("google_storage_object_access_control", "a", map[string]ir.Value{
		"entity": ks("allAuthenticatedUsers", 3),
		"role":   ks("READER", 4),
	})), "AEGIS-GCP-186")
	mustQuiet(t, runRule(bucketDefObjACLPublic{}, res("google_storage_default_object_access_control", "a", map[string]ir.Value{
		"entity": ks("user-alice@example.com", 3),
	})))
	mustQuiet(t, runRule(bucketDefObjACLPublic{}, res("google_storage_default_object_access_control", "a", map[string]ir.Value{
		"entity": ku(3),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-187/188/189/190: GCS retention lock, domain admin, CORS, write
// ---------------------------------------------------------------------------

func TestGCP187_190(t *testing.T) {
	// 187: retention policy not locked
	mustFinding(t, runRule(bucketRetentionUnlocked{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"retention_policy": blks(3, blk("retention_period", kn(86400, 4))),
	})), "AEGIS-GCP-187")
	mustQuiet(t, runRule(bucketRetentionUnlocked{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"retention_policy": blks(3, blk("retention_period", kn(86400, 4), "is_locked", kv(true, 5))),
	})))
	mustQuiet(t, runRule(bucketRetentionUnlocked{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"retention_policy": blks(3, blk("is_locked", ku(4))),
	})))
	mustQuiet(t, runRule(bucketRetentionUnlocked{}, res("google_storage_bucket", "b", nil)))

	// 188: domain-wide admin (member + binding variants)
	mustFinding(t, runRule(bucketIAMDomainAdmin{}, res("google_storage_bucket_iam_member", "m", map[string]ir.Value{
		"role":   ks("roles/storage.admin", 3),
		"member": ks("domain:example.com", 4),
	})), "AEGIS-GCP-188")
	mustFinding(t, runRule(bucketIAMDomainAdmin{}, res("google_storage_bucket_iam_binding", "b", map[string]ir.Value{
		"role":    ks("roles/storage.admin", 3),
		"members": strList(4, "group:eng@example.com", "domain:example.com"),
	})), "AEGIS-GCP-188")
	mustQuiet(t, runRule(bucketIAMDomainAdmin{}, res("google_storage_bucket_iam_member", "m", map[string]ir.Value{
		"role":   ks("roles/storage.admin", 3),
		"member": ks("group:eng@example.com", 4),
	})))
	mustQuiet(t, runRule(bucketIAMDomainAdmin{}, res("google_storage_bucket_iam_member", "m", map[string]ir.Value{
		"role":   ks("roles/storage.objectViewer", 3),
		"member": ks("domain:example.com", 4),
	})))
	mustQuiet(t, runRule(bucketIAMDomainAdmin{}, res("google_storage_bucket_iam_member", "m", map[string]ir.Value{
		"role":   ks("roles/storage.admin", 3),
		"member": ku(4),
	})))

	// 189: CORS with http:// origin
	mustFinding(t, runRule(bucketCORSInsecureOrigin{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"cors": blks(3, blk("origin", strList(4, "http://example.com"), "method", strList(5, "GET"))),
	})), "AEGIS-GCP-189")
	mustQuiet(t, runRule(bucketCORSInsecureOrigin{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"cors": blks(3, blk("origin", strList(4, "https://example.com"))),
	})))
	mustQuiet(t, runRule(bucketCORSInsecureOrigin{}, res("google_storage_bucket", "b", map[string]ir.Value{
		"cors": blks(3, blk("origin", ku(4))),
	})))

	// 190: public write via objectCreator
	f := mustFinding(t, runRule(bucketIAMPublicWrite{}, res("google_storage_bucket_iam_binding", "b", map[string]ir.Value{
		"role":    ks("roles/storage.objectCreator", 3),
		"members": strList(4, "allUsers"),
	})), "AEGIS-GCP-190")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("190: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(bucketIAMPublicWrite{}, res("google_storage_bucket_iam_binding", "b", map[string]ir.Value{
		"role":    ks("roles/storage.objectViewer", 3),
		"members": strList(4, "allUsers"),
	})))
	mustQuiet(t, runRule(bucketIAMPublicWrite{}, res("google_storage_bucket_iam_member", "m", map[string]ir.Value{
		"role":   ks("roles/storage.objectCreator", 3),
		"member": ku(4),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-191..194: BigQuery
// ---------------------------------------------------------------------------

func TestGCP191_194(t *testing.T) {
	// 191: bigquery.admin grant
	mustFinding(t, runRule(bqDatasetAdminGrant{}, res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("role", ks("roles/bigquery.admin", 4), "special_group", ks("projectOwners", 5))),
	})), "AEGIS-GCP-191")
	mustQuiet(t, runRule(bqDatasetAdminGrant{}, res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("role", ks("roles/bigquery.dataViewer", 4))),
	})))
	mustQuiet(t, runRule(bqDatasetAdminGrant{}, res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("role", ku(4))),
	})))

	// 192: table IAM public
	f := mustFinding(t, runRule(bqTableIAMPublic{}, res("google_bigquery_table_iam_binding", "b", map[string]ir.Value{
		"role":    ks("roles/bigquery.dataViewer", 3),
		"members": strList(4, "allUsers"),
	})), "AEGIS-GCP-192")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("192: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(bqTableIAMPublic{}, res("google_bigquery_table_iam_member", "m", map[string]ir.Value{
		"role":   ks("roles/bigquery.dataViewer", 3),
		"member": ks("user:alice@example.com", 4),
	})))
	mustQuiet(t, runRule(bqTableIAMPublic{}, res("google_bigquery_table_iam_binding", "b", map[string]ir.Value{
		"role":    ks("roles/bigquery.dataViewer", 3),
		"members": ku(4),
	})))

	// 193: table deletion protection explicitly false
	mustFinding(t, runRule(bqTableNoDelProtect{}, res("google_bigquery_table", "t",
		map[string]ir.Value{"deletion_protection": kv(false, 3)})), "AEGIS-GCP-193")
	mustQuiet(t, runRule(bqTableNoDelProtect{}, res("google_bigquery_table", "t",
		map[string]ir.Value{"deletion_protection": kv(true, 3)})))
	mustQuiet(t, runRule(bqTableNoDelProtect{}, res("google_bigquery_table", "t", nil)))
	mustQuiet(t, runRule(bqTableNoDelProtect{}, res("google_bigquery_table", "t",
		map[string]ir.Value{"deletion_protection": ku(3)})))

	// 194: dataOwner grant
	mustFinding(t, runRule(bqDatasetDataOwnerGrant{}, res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("role", ks("roles/bigquery.dataOwner", 4))),
	})), "AEGIS-GCP-194")
	mustQuiet(t, runRule(bqDatasetDataOwnerGrant{}, res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("role", ks("roles/bigquery.dataEditor", 4))),
	})))
	mustQuiet(t, runRule(bqDatasetDataOwnerGrant{}, res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("role", ku(4))),
	})))

}

// ---------------------------------------------------------------------------
// AEGIS-GCP-196..199: Cloud Run v2 hardening
// ---------------------------------------------------------------------------

func TestGCP196_199(t *testing.T) {
	runTpl := func(inner map[string]ir.Value) ir.Resource {
		return res("google_cloud_run_v2_service", "s", map[string]ir.Value{
			"template": blks(3, inner),
		})
	}

	// 196: mutable image tag
	mustFinding(t, runRule(runImageLatestTag{}, runTpl(blk("containers",
		blks(4, blk("image", ks("gcr.io/p/app:latest", 5)))))), "AEGIS-GCP-196")
	mustFinding(t, runRule(runImageLatestTag{}, runTpl(blk("containers",
		blks(4, blk("image", ks("gcr.io/p/app", 5)))))), "AEGIS-GCP-196")
	mustQuiet(t, runRule(runImageLatestTag{}, runTpl(blk("containers",
		blks(4, blk("image", ks("gcr.io/p/app:v1.2.3", 5)))))))
	mustQuiet(t, runRule(runImageLatestTag{}, runTpl(blk("containers",
		blks(4, blk("image", ku(5)))))))

	// 197: no VPC access
	mustFinding(t, runRule(runNoVPCAccess{}, runTpl(blk("service_account", ks("sa@x.iam.gserviceaccount.com", 4)))), "AEGIS-GCP-197")
	mustQuiet(t, runRule(runNoVPCAccess{}, runTpl(blk("vpc_access",
		blks(4, blk("connector", ks("c", 5)))))))
	mustQuiet(t, runRule(runNoVPCAccess{}, res("google_cloud_run_v2_service", "s", map[string]ir.Value{
		"template": ku(3),
	})))

	// 198: no binary authorization
	mustFinding(t, runRule(runNoBinaryAuthz{}, res("google_cloud_run_v2_service", "s", nil)), "AEGIS-GCP-198")
	mustQuiet(t, runRule(runNoBinaryAuthz{}, res("google_cloud_run_v2_service", "s", map[string]ir.Value{
		"binary_authorization": blks(3),
	})))
	mustQuiet(t, runRule(runNoBinaryAuthz{}, res("google_cloud_run_v2_service", "s", map[string]ir.Value{
		"binary_authorization": ku(3),
	})))

	// 199: Gen1 execution environment
	mustFinding(t, runRule(runGen1ExecEnv{}, runTpl(blk("execution_environment", ks("EXECUTION_ENVIRONMENT_GEN1", 4)))), "AEGIS-GCP-199")
	mustQuiet(t, runRule(runGen1ExecEnv{}, runTpl(blk("execution_environment", ks("EXECUTION_ENVIRONMENT_GEN2", 4)))))
	mustQuiet(t, runRule(runGen1ExecEnv{}, runTpl(blk("service_account", ks("sa@x.iam.gserviceaccount.com", 4)))))
	mustQuiet(t, runRule(runGen1ExecEnv{}, res("google_cloud_run_v2_service", "s", map[string]ir.Value{
		"template": ku(3),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-200..203: Cloud Functions
// ---------------------------------------------------------------------------

func TestGCP200_203(t *testing.T) {
	// 200: EOL runtime (gen1 + gen2 shapes)
	f := mustFinding(t, runRule(functionsEOLRuntime{}, res("google_cloudfunctions_function", "f",
		map[string]ir.Value{"runtime": ks("nodejs16", 3)})), "AEGIS-GCP-200")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("200: wrong severity %s", f.Severity)
	}
	mustFinding(t, runRule(functionsEOLRuntime{}, res("google_cloudfunctions2_function", "f", map[string]ir.Value{
		"build_config": blks(3, blk("runtime", ks("python39", 4))),
	})), "AEGIS-GCP-200")
	mustQuiet(t, runRule(functionsEOLRuntime{}, res("google_cloudfunctions_function", "f",
		map[string]ir.Value{"runtime": ks("nodejs20", 3)})))
	mustQuiet(t, runRule(functionsEOLRuntime{}, res("google_cloudfunctions2_function", "f", map[string]ir.Value{
		"build_config": blks(3, blk("runtime", ks("python312", 4))),
	})))
	mustQuiet(t, runRule(functionsEOLRuntime{}, res("google_cloudfunctions_function", "f",
		map[string]ir.Value{"runtime": ku(3)})))

	// 201: no VPC connector
	mustFinding(t, runRule(functionsNoVPCConnector{}, res("google_cloudfunctions2_function", "f", map[string]ir.Value{
		"service_config": blks(3, blk("max_instance_count", kn(10, 4))),
	})), "AEGIS-GCP-201")
	mustQuiet(t, runRule(functionsNoVPCConnector{}, res("google_cloudfunctions2_function", "f", map[string]ir.Value{
		"service_config": blks(3, blk("vpc_connector", ks("projects/p/locations/l/connectors/c", 4))),
	})))
	mustQuiet(t, runRule(functionsNoVPCConnector{}, res("google_cloudfunctions2_function", "f", map[string]ir.Value{
		"service_config": ku(3),
	})))
	mustQuiet(t, runRule(functionsNoVPCConnector{}, res("google_cloudfunctions2_function", "f", nil)))

	// 202: 1st-gen function resource
	mustFinding(t, runRule(functionsGen1Resource{}, res("google_cloudfunctions_function", "f", nil)), "AEGIS-GCP-202")
	mustQuiet(t, runRule(functionsGen1Resource{}, res("google_cloudfunctions2_function", "f", nil)))
	mustQuiet(t, runRule(functionsGen1Resource{}, res("google_cloud_run_v2_service", "s", nil)))

	// 203: explicit default compute SA
	mustFinding(t, runRule(runDefaultComputeSAExp{}, res("google_cloud_run_v2_service", "s", map[string]ir.Value{
		"template": blks(3, blk("service_account", ks("123456789-compute@developer.gserviceaccount.com", 4))),
	})), "AEGIS-GCP-203")
	mustQuiet(t, runRule(runDefaultComputeSAExp{}, res("google_cloud_run_v2_service", "s", map[string]ir.Value{
		"template": blks(3, blk("service_account", ks("sa@proj.iam.gserviceaccount.com", 4))),
	})))
	mustQuiet(t, runRule(runDefaultComputeSAExp{}, res("google_cloud_run_v2_service", "s", map[string]ir.Value{
		"template": blks(3, blk("service_account", ku(4))),
	})))
	mustQuiet(t, runRule(runDefaultComputeSAExp{}, res("google_cloud_run_v2_service", "s", map[string]ir.Value{
		"template": blks(3, blk("containers", blks(4))),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-204..209: Pub/Sub
// ---------------------------------------------------------------------------

func TestGCP204_209(t *testing.T) {
	// 204: no message storage policy
	mustFinding(t, runRule(pubsubNoStoragePolicy{}, res("google_pubsub_topic", "t", nil)), "AEGIS-GCP-204")
	mustQuiet(t, runRule(pubsubNoStoragePolicy{}, res("google_pubsub_topic", "t", map[string]ir.Value{
		"message_storage_policy": blks(3, blk("allowed_persistence_regions", strList(4, "us-central1"))),
	})))
	mustQuiet(t, runRule(pubsubNoStoragePolicy{}, res("google_pubsub_topic", "t", map[string]ir.Value{
		"message_storage_policy": ku(3),
	})))

	// 205: subscription IAM public
	f := mustFinding(t, runRule(pubsubSubIAMPublic{}, res("google_pubsub_subscription_iam_binding", "b", map[string]ir.Value{
		"role":    ks("roles/pubsub.subscriber", 3),
		"members": strList(4, "allUsers"),
	})), "AEGIS-GCP-205")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("205: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(pubsubSubIAMPublic{}, res("google_pubsub_subscription_iam_member", "m", map[string]ir.Value{
		"role":   ks("roles/pubsub.viewer", 3),
		"member": ks("user:alice@example.com", 4),
	})))
	mustQuiet(t, runRule(pubsubSubIAMPublic{}, res("google_pubsub_subscription_iam_binding", "b", map[string]ir.Value{
		"role":    ks("roles/pubsub.subscriber", 3),
		"members": ku(4),
	})))

	// 206: retain_acked_messages explicitly false
	mustFinding(t, runRule(pubsubNoRetainAcked{}, res("google_pubsub_subscription", "s",
		map[string]ir.Value{"retain_acked_messages": kv(false, 3)})), "AEGIS-GCP-206")
	mustQuiet(t, runRule(pubsubNoRetainAcked{}, res("google_pubsub_subscription", "s",
		map[string]ir.Value{"retain_acked_messages": kv(true, 3)})))
	mustQuiet(t, runRule(pubsubNoRetainAcked{}, res("google_pubsub_subscription", "s", nil)))
	mustQuiet(t, runRule(pubsubNoRetainAcked{}, res("google_pubsub_subscription", "s",
		map[string]ir.Value{"retain_acked_messages": ku(3)})))

	// 207: retention under 7 days
	mustFinding(t, runRule(pubsubShortRetention{}, res("google_pubsub_topic", "t",
		map[string]ir.Value{"message_retention_duration": ks("3600s", 3)})), "AEGIS-GCP-207")
	mustQuiet(t, runRule(pubsubShortRetention{}, res("google_pubsub_topic", "t",
		map[string]ir.Value{"message_retention_duration": ks("1209600s", 3)})))
	mustQuiet(t, runRule(pubsubShortRetention{}, res("google_pubsub_topic", "t",
		map[string]ir.Value{"message_retention_duration": ks("604800s", 3)})))
	mustQuiet(t, runRule(pubsubShortRetention{}, res("google_pubsub_topic", "t", nil)))
	mustQuiet(t, runRule(pubsubShortRetention{}, res("google_pubsub_topic", "t",
		map[string]ir.Value{"message_retention_duration": ku(3)})))
	mustQuiet(t, runRule(pubsubShortRetention{}, res("google_pubsub_topic", "t",
		map[string]ir.Value{"message_retention_duration": ks("not-a-duration", 3)})))

	// 208: no schema validation
	mustFinding(t, runRule(pubsubNoSchema{}, res("google_pubsub_topic", "t", nil)), "AEGIS-GCP-208")
	mustQuiet(t, runRule(pubsubNoSchema{}, res("google_pubsub_topic", "t", map[string]ir.Value{
		"schema_settings": blks(3, blk("schema", ks("projects/p/schemas/s", 4))),
	})))
	mustQuiet(t, runRule(pubsubNoSchema{}, res("google_pubsub_topic", "t", map[string]ir.Value{
		"schema_settings": ku(3),
	})))

	// 209: no retry policy
	mustFinding(t, runRule(pubsubNoRetryPolicy{}, res("google_pubsub_subscription", "s", nil)), "AEGIS-GCP-209")
	mustQuiet(t, runRule(pubsubNoRetryPolicy{}, res("google_pubsub_subscription", "s", map[string]ir.Value{
		"retry_policy": blks(3, blk("minimum_backoff", ks("10s", 4))),
	})))
	mustQuiet(t, runRule(pubsubNoRetryPolicy{}, res("google_pubsub_subscription", "s", map[string]ir.Value{
		"retry_policy": ku(3),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-210..213: backend service / SSL policy
// ---------------------------------------------------------------------------

func TestGCP210_213(t *testing.T) {
	// 210: backend without health checks
	mustFinding(t, runRule(backendNoHealthCheck{}, res("google_compute_backend_service", "b", nil)), "AEGIS-GCP-210")
	mustQuiet(t, runRule(backendNoHealthCheck{}, res("google_compute_backend_service", "b", map[string]ir.Value{
		"health_checks": strList(3, "https://www.googleapis.com/compute/v1/projects/p/global/healthChecks/hc"),
	})))
	mustQuiet(t, runRule(backendNoHealthCheck{}, res("google_compute_backend_service", "b", map[string]ir.Value{
		"health_checks": ku(3),
	})))

	// 211: backend without IAP
	mustFinding(t, runRule(backendNoIAP{}, res("google_compute_backend_service", "b", nil)), "AEGIS-GCP-211")
	mustQuiet(t, runRule(backendNoIAP{}, res("google_compute_backend_service", "b", map[string]ir.Value{
		"iap": blks(3, blk("oauth2_client_id", ks("id", 4))),
	})))
	mustQuiet(t, runRule(backendNoIAP{}, res("google_compute_backend_service", "b", map[string]ir.Value{
		"iap": ku(3),
	})))

	// 212: COMPATIBLE SSL profile
	mustFinding(t, runRule(sslCompatibleProfile{}, res("google_compute_ssl_policy", "p",
		map[string]ir.Value{"profile": ks("COMPATIBLE", 3)})), "AEGIS-GCP-212")
	mustQuiet(t, runRule(sslCompatibleProfile{}, res("google_compute_ssl_policy", "p",
		map[string]ir.Value{"profile": ks("MODERN", 3)})))
	mustQuiet(t, runRule(sslCompatibleProfile{}, res("google_compute_ssl_policy", "p", nil)))
	mustQuiet(t, runRule(sslCompatibleProfile{}, res("google_compute_ssl_policy", "p",
		map[string]ir.Value{"profile": ku(3)})))

	// 213: plaintext HTTP backend protocol
	mustFinding(t, runRule(backendPlainHTTP{}, res("google_compute_backend_service", "b",
		map[string]ir.Value{"protocol": ks("HTTP", 3)})), "AEGIS-GCP-213")
	mustQuiet(t, runRule(backendPlainHTTP{}, res("google_compute_backend_service", "b",
		map[string]ir.Value{"protocol": ks("HTTPS", 3)})))
	mustQuiet(t, runRule(backendPlainHTTP{}, res("google_compute_backend_service", "b", nil)))
	mustQuiet(t, runRule(backendPlainHTTP{}, res("google_compute_backend_service", "b",
		map[string]ir.Value{"protocol": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-214/215: firewall all-ports / description
// ---------------------------------------------------------------------------

func TestGCP214_215(t *testing.T) {
	// 214: allow to world with ports omitted (all ports)
	f := mustFinding(t, runRule(fwAllPortsNoPortsList{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": strList(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5))),
	})), "AEGIS-GCP-214")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("214: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(fwAllPortsNoPortsList{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": strList(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5), "ports", strList(6, "443"))),
	})))
	mustQuiet(t, runRule(fwAllPortsNoPortsList{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": strList(3, "10.0.0.0/8"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5))),
	})))
	mustQuiet(t, runRule(fwAllPortsNoPortsList{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": strList(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("icmp", 5))),
	})))
	mustQuiet(t, runRule(fwAllPortsNoPortsList{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": strList(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5), "ports", ku(6))),
	})))
	mustQuiet(t, runRule(fwAllPortsNoPortsList{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": ku(3),
		"allow":         blks(4, blk("protocol", ks("tcp", 5))),
	})))

	// 215: no description
	mustFinding(t, runRule(fwNoDescription{}, res("google_compute_firewall", "f", nil)), "AEGIS-GCP-215")
	mustQuiet(t, runRule(fwNoDescription{}, res("google_compute_firewall", "f",
		map[string]ir.Value{"description": ks("allow https from lb", 3)})))
	mustQuiet(t, runRule(fwNoDescription{}, res("google_compute_firewall", "f",
		map[string]ir.Value{"description": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-216..219: subnetwork, NAT, SSL ciphers
// ---------------------------------------------------------------------------

func TestGCP216_219(t *testing.T) {
	// 216: external IPv6
	mustFinding(t, runRule(subnetExternalIPv6{}, res("google_compute_subnetwork", "s",
		map[string]ir.Value{"ipv6_access_type": ks("EXTERNAL", 3)})), "AEGIS-GCP-216")
	mustQuiet(t, runRule(subnetExternalIPv6{}, res("google_compute_subnetwork", "s",
		map[string]ir.Value{"ipv6_access_type": ks("INTERNAL", 3)})))
	mustQuiet(t, runRule(subnetExternalIPv6{}, res("google_compute_subnetwork", "s", nil)))
	mustQuiet(t, runRule(subnetExternalIPv6{}, res("google_compute_subnetwork", "s",
		map[string]ir.Value{"ipv6_access_type": ku(3)})))

	// 217: private Google access unset
	mustFinding(t, runRule(subnetNoPGAUnset{}, res("google_compute_subnetwork", "s", nil)), "AEGIS-GCP-217")
	mustQuiet(t, runRule(subnetNoPGAUnset{}, res("google_compute_subnetwork", "s",
		map[string]ir.Value{"private_ip_google_access": kv(true, 3)})))
	mustQuiet(t, runRule(subnetNoPGAUnset{}, res("google_compute_subnetwork", "s",
		map[string]ir.Value{"private_ip_google_access": kv(false, 3)})))
	mustQuiet(t, runRule(subnetNoPGAUnset{}, res("google_compute_subnetwork", "s",
		map[string]ir.Value{"private_ip_google_access": ku(3)})))

	// 218: NAT without logging
	mustFinding(t, runRule(routerNATNoLogging{}, res("google_compute_router_nat", "n", nil)), "AEGIS-GCP-218")
	mustQuiet(t, runRule(routerNATNoLogging{}, res("google_compute_router_nat", "n", map[string]ir.Value{
		"log_config": blks(3, blk("enable", kv(true, 4))),
	})))
	mustQuiet(t, runRule(routerNATNoLogging{}, res("google_compute_router_nat", "n", map[string]ir.Value{
		"log_config": ku(3),
	})))

	// 219: weak custom ciphers
	f := mustFinding(t, runRule(sslWeakCustomCiphers{}, res("google_compute_ssl_policy", "p", map[string]ir.Value{
		"custom_features": strList(3, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA"),
	})), "AEGIS-GCP-219")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("219: wrong severity %s", f.Severity)
	}
	mustFinding(t, runRule(sslWeakCustomCiphers{}, res("google_compute_ssl_policy", "p", map[string]ir.Value{
		"custom_features": strList(3, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
	})), "AEGIS-GCP-219")
	mustQuiet(t, runRule(sslWeakCustomCiphers{}, res("google_compute_ssl_policy", "p", map[string]ir.Value{
		"custom_features": strList(3, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
	})))
	mustQuiet(t, runRule(sslWeakCustomCiphers{}, res("google_compute_ssl_policy", "p", nil)))
	mustQuiet(t, runRule(sslWeakCustomCiphers{}, res("google_compute_ssl_policy", "p", map[string]ir.Value{
		"custom_features": ku(3),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-220/221/222: target pool, VPC mode, firewall log metadata
// ---------------------------------------------------------------------------

func TestGCP220_222(t *testing.T) {
	// 220: target pool without health checks
	mustFinding(t, runRule(targetPoolNoHealthCheck{}, res("google_compute_target_pool", "p", nil)), "AEGIS-GCP-220")
	mustQuiet(t, runRule(targetPoolNoHealthCheck{}, res("google_compute_target_pool", "p", map[string]ir.Value{
		"health_checks": strList(3, "hc"),
	})))
	mustQuiet(t, runRule(targetPoolNoHealthCheck{}, res("google_compute_target_pool", "p", map[string]ir.Value{
		"health_checks": ku(3),
	})))

	// 221: auto-mode VPC
	mustFinding(t, runRule(networkAutoSubnetworks{}, res("google_compute_network", "n", nil)), "AEGIS-GCP-221")
	mustFinding(t, runRule(networkAutoSubnetworks{}, res("google_compute_network", "n",
		map[string]ir.Value{"auto_create_subnetworks": kv(true, 3)})), "AEGIS-GCP-221")
	mustQuiet(t, runRule(networkAutoSubnetworks{}, res("google_compute_network", "n",
		map[string]ir.Value{"auto_create_subnetworks": kv(false, 3)})))
	mustQuiet(t, runRule(networkAutoSubnetworks{}, res("google_compute_network", "n",
		map[string]ir.Value{"auto_create_subnetworks": ku(3)})))

	// 222: firewall log metadata excluded
	mustFinding(t, runRule(fwLoggingNoMetadata{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"log_config": blks(3, blk("metadata", ks("EXCLUDE_ALL_METADATA", 4))),
	})), "AEGIS-GCP-222")
	mustQuiet(t, runRule(fwLoggingNoMetadata{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"log_config": blks(3, blk("metadata", ks("INCLUDE_ALL_METADATA", 4))),
	})))
	mustQuiet(t, runRule(fwLoggingNoMetadata{}, res("google_compute_firewall", "f", nil)))
	mustQuiet(t, runRule(fwLoggingNoMetadata{}, res("google_compute_firewall", "f", map[string]ir.Value{
		"log_config": blks(3, blk("metadata", ku(4))),
	})))
}
