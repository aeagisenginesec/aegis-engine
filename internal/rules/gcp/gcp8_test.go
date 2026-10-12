package gcp

import (
	"testing"

	"aegis/internal/ir"
)

// Pack registration: GCP8Rules must return rules 223..262 in ID order.
// (Wiring into Rules() is handled separately, as with GCP9Rules.)
func TestGCP8RulesInIDOrder(t *testing.T) {
	rules := GCP8Rules()
	if len(rules) != 40 {
		t.Fatalf("expected 40 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := "AEGIS-GCP-" + itoa(223+i)
		if r.ID() != want {
			t.Fatalf("rule %d: want %s, got %s", i, want, r.ID())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %s missing title/description", want)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-223: KMS key ring in global location
// ---------------------------------------------------------------------------

func TestGCP223(t *testing.T) {
	mustFinding(t, runRule(kmsKeyRingGlobalLocation{}, res("google_kms_key_ring", "k",
		map[string]ir.Value{"location": ks("global", 3)})), "AEGIS-GCP-223")
	mustFinding(t, runRule(kmsKeyRingGlobalLocation{}, res("google_kms_key_ring", "k", nil)), "AEGIS-GCP-223")
	mustQuiet(t, runRule(kmsKeyRingGlobalLocation{}, res("google_kms_key_ring", "k",
		map[string]ir.Value{"location": ks("europe-west1", 3)})))
	mustQuiet(t, runRule(kmsKeyRingGlobalLocation{}, res("google_kms_key_ring", "k",
		map[string]ir.Value{"location": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-224: KMS crypto key with very short destroy-scheduled duration
// ---------------------------------------------------------------------------

func TestGCP224(t *testing.T) {
	mustFinding(t, runRule(kmsShortDestroyDuration{}, res("google_kms_crypto_key", "k",
		map[string]ir.Value{"destroy_scheduled_duration": ks("3600s", 3)})), "AEGIS-GCP-224")
	mustQuiet(t, runRule(kmsShortDestroyDuration{}, res("google_kms_crypto_key", "k",
		map[string]ir.Value{"destroy_scheduled_duration": ks("86400s", 3)})))
	mustQuiet(t, runRule(kmsShortDestroyDuration{}, res("google_kms_crypto_key", "k", nil)))
	mustQuiet(t, runRule(kmsShortDestroyDuration{}, res("google_kms_crypto_key", "k",
		map[string]ir.Value{"destroy_scheduled_duration": ku(3)})))
	mustQuiet(t, runRule(kmsShortDestroyDuration{}, res("google_kms_crypto_key", "k",
		map[string]ir.Value{"destroy_scheduled_duration": ks("soon", 3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-225: KMS crypto key with software protection level
// ---------------------------------------------------------------------------

func TestGCP225(t *testing.T) {
	mustFinding(t, runRule(kmsSoftwareProtectionLevel{}, res("google_kms_crypto_key", "k",
		map[string]ir.Value{"version_template": blks(3, blk("protection_level", ks("SOFTWARE", 4)))})), "AEGIS-GCP-225")
	mustQuiet(t, runRule(kmsSoftwareProtectionLevel{}, res("google_kms_crypto_key", "k",
		map[string]ir.Value{"version_template": blks(3, blk("protection_level", ks("HSM", 4)))})))
	mustQuiet(t, runRule(kmsSoftwareProtectionLevel{}, res("google_kms_crypto_key", "k", nil)))
	mustQuiet(t, runRule(kmsSoftwareProtectionLevel{}, res("google_kms_crypto_key", "k",
		map[string]ir.Value{"version_template": blks(3, blk("protection_level", ku(4)))})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-226: Secret Manager secret IAM grants to the public
// ---------------------------------------------------------------------------

func TestGCP226(t *testing.T) {
	f := mustFinding(t, runRule(secretManagerPublicIAM{}, res("google_secret_manager_secret_iam_binding", "b",
		map[string]ir.Value{"role": ks("roles/secretmanager.secretAccessor", 3), "members": strList(4, "allUsers")})), "AEGIS-GCP-226")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustFinding(t, runRule(secretManagerPublicIAM{}, res("google_secret_manager_secret_iam_member", "m",
		map[string]ir.Value{"role": ks("roles/secretmanager.viewer", 3), "member": ks("allAuthenticatedUsers", 4)})), "AEGIS-GCP-226")
	mustQuiet(t, runRule(secretManagerPublicIAM{}, res("google_secret_manager_secret_iam_binding", "b",
		map[string]ir.Value{"role": ks("roles/secretmanager.secretAccessor", 3), "members": strList(4, "user:ops@example.com")})))
	mustQuiet(t, runRule(secretManagerPublicIAM{}, res("google_secret_manager_secret_iam_binding", "b",
		map[string]ir.Value{"role": ks("roles/secretmanager.secretAccessor", 3), "members": ku(4)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-227: Secret Manager secret value in Terraform state
// ---------------------------------------------------------------------------

func TestGCP227(t *testing.T) {
	f := mustFinding(t, runRule(secretDataInState{}, res("google_secret_manager_secret_version", "v",
		map[string]ir.Value{"secret_data": ks("supersecret", 3)})), "AEGIS-GCP-227")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(secretDataInState{}, res("google_secret_manager_secret_version", "v", nil)))
	mustQuiet(t, runRule(secretDataInState{}, res("google_secret_manager_secret_version", "v",
		map[string]ir.Value{"secret_data": ku(3)})))
	mustQuiet(t, runRule(secretDataInState{}, res("google_secret_manager_secret_version", "v",
		map[string]ir.Value{"secret_data": ks("", 3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-228/229: Secret Manager replication shape
// ---------------------------------------------------------------------------

func TestGCP228_229(t *testing.T) {
	// 228: automatic replication
	mustFinding(t, runRule(secretAutomaticReplication{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"replication": blks(3, blk("automatic", blks(4)))})), "AEGIS-GCP-228")
	mustQuiet(t, runRule(secretAutomaticReplication{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"replication": blks(3, blk("user_managed", blks(4)))})))
	mustQuiet(t, runRule(secretAutomaticReplication{}, res("google_secret_manager_secret", "s", nil)))
	mustQuiet(t, runRule(secretAutomaticReplication{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"replication": ku(3)})))

	// 229: single replica region
	mustFinding(t, runRule(secretSingleRegionReplication{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"replication": blks(3, blk("user_managed",
			blks(4, blk("replicas", blks(5, blk("location", ks("us-central1", 6)))))))})), "AEGIS-GCP-229")
	mustQuiet(t, runRule(secretSingleRegionReplication{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"replication": blks(3, blk("user_managed",
			blks(4, blk("replicas", blks(5,
				blk("location", ks("us-central1", 6)),
				blk("location", ks("us-east1", 6)))))))})))
	mustQuiet(t, runRule(secretSingleRegionReplication{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"replication": blks(3, blk("automatic", blks(4)))})))
	mustQuiet(t, runRule(secretSingleRegionReplication{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"replication": blks(3, blk("user_managed",
			blks(4, blk("replicas", ku(5)))))})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-230/231: Secret Manager rotation period
// ---------------------------------------------------------------------------

func TestGCP230_231(t *testing.T) {
	// 230: rotation block without a period
	mustFinding(t, runRule(secretRotationMissingPeriod{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"rotation": blks(3, blk("next_rotation_time", ks("2027-01-01T00:00:00Z", 4)))})), "AEGIS-GCP-230")
	mustQuiet(t, runRule(secretRotationMissingPeriod{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"rotation": blks(3, blk("rotation_period", ks("7776000s", 4)))})))
	mustQuiet(t, runRule(secretRotationMissingPeriod{}, res("google_secret_manager_secret", "s", nil)))
	mustQuiet(t, runRule(secretRotationMissingPeriod{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"rotation": ku(3)})))
	mustQuiet(t, runRule(secretRotationMissingPeriod{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"rotation": blks(3, blk("rotation_period", ku(4)))})))

	// 231: rotation period over 90 days
	mustFinding(t, runRule(secretLongRotationPeriod{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"rotation": blks(3, blk("rotation_period", ks("31536000s", 4)))})), "AEGIS-GCP-231")
	mustQuiet(t, runRule(secretLongRotationPeriod{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"rotation": blks(3, blk("rotation_period", ks("7776000s", 4)))})))
	mustQuiet(t, runRule(secretLongRotationPeriod{}, res("google_secret_manager_secret", "s", nil)))
	mustQuiet(t, runRule(secretLongRotationPeriod{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"rotation": blks(3, blk("rotation_period", ku(4)))})))
	mustQuiet(t, runRule(secretLongRotationPeriod{}, res("google_secret_manager_secret", "s",
		map[string]ir.Value{"rotation": blks(3, blk("rotation_period", ks("ninety days", 4)))})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-232: Logging sink filter excludes security logs
// ---------------------------------------------------------------------------

func TestGCP232(t *testing.T) {
	mustFinding(t, runRule(logSinkSeverityExclusion{}, res("google_logging_project_sink", "s",
		map[string]ir.Value{"filter": ks("severity < WARNING", 3)})), "AEGIS-GCP-232")
	mustFinding(t, runRule(logSinkSeverityExclusion{}, res("google_logging_folder_sink", "s",
		map[string]ir.Value{"filter": ks("resource.type=gce AND severity<ERROR", 3)})), "AEGIS-GCP-232")
	mustQuiet(t, runRule(logSinkSeverityExclusion{}, res("google_logging_project_sink", "s",
		map[string]ir.Value{"filter": ks("severity >= ERROR", 3)})))
	mustQuiet(t, runRule(logSinkSeverityExclusion{}, res("google_logging_project_sink", "s", nil)))
	mustQuiet(t, runRule(logSinkSeverityExclusion{}, res("google_logging_project_sink", "s",
		map[string]ir.Value{"filter": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-233/234/235/236: Log bucket retention & CMEK
// ---------------------------------------------------------------------------

func TestGCP233_236(t *testing.T) {
	// 233: no retention days, or unlocked via explicit locked=false
	mustFinding(t, runRule(logBucketNoLockedRetention{}, res("google_logging_project_bucket_config", "b", nil)), "AEGIS-GCP-233")
	mustFinding(t, runRule(logBucketNoLockedRetention{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(30, 3), "locked": kv(false, 4)})), "AEGIS-GCP-233")
	mustQuiet(t, runRule(logBucketNoLockedRetention{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(30, 3), "locked": kv(true, 4)})))
	mustQuiet(t, runRule(logBucketNoLockedRetention{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": ku(3)})))
	mustQuiet(t, runRule(logBucketNoLockedRetention{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(30, 3), "locked": ku(4)})))

	// 234: no CMEK
	mustFinding(t, runRule(logBucketNoCMEK{}, res("google_logging_project_bucket_config", "b", nil)), "AEGIS-GCP-234")
	mustQuiet(t, runRule(logBucketNoCMEK{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"cmek_settings": blks(3, blk("kms_key_name", ks("k", 4)))})))
	mustQuiet(t, runRule(logBucketNoCMEK{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"cmek_settings": ku(3)})))

	// 235: retention under 30 days
	mustFinding(t, runRule(logBucketShortRetention{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(7, 3)})), "AEGIS-GCP-235")
	mustQuiet(t, runRule(logBucketShortRetention{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(90, 3)})))
	mustQuiet(t, runRule(logBucketShortRetention{}, res("google_logging_project_bucket_config", "b", nil)))
	mustQuiet(t, runRule(logBucketShortRetention{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": ku(3)})))

	// 236: retention set but not locked
	mustFinding(t, runRule(logBucketRetentionUnlocked{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(90, 3)})), "AEGIS-GCP-236")
	mustQuiet(t, runRule(logBucketRetentionUnlocked{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(90, 3), "locked": kv(true, 4)})))
	mustQuiet(t, runRule(logBucketRetentionUnlocked{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(90, 3), "locked": kv(false, 4)})))
	mustQuiet(t, runRule(logBucketRetentionUnlocked{}, res("google_logging_project_bucket_config", "b",
		map[string]ir.Value{"retention_days": kn(90, 3), "locked": ku(4)})))
	mustQuiet(t, runRule(logBucketRetentionUnlocked{}, res("google_logging_project_bucket_config", "b", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-237: Monitoring alert policy without notification channels
// ---------------------------------------------------------------------------

func TestGCP237(t *testing.T) {
	mustFinding(t, runRule(alertPolicyNoNotificationChannels{}, res("google_monitoring_alert_policy", "a", nil)), "AEGIS-GCP-237")
	mustFinding(t, runRule(alertPolicyNoNotificationChannels{}, res("google_monitoring_alert_policy", "a",
		map[string]ir.Value{"notification_channels": strList(3)})), "AEGIS-GCP-237")
	mustQuiet(t, runRule(alertPolicyNoNotificationChannels{}, res("google_monitoring_alert_policy", "a",
		map[string]ir.Value{"notification_channels": strList(3, "projects/p/notificationChannels/1")})))
	mustQuiet(t, runRule(alertPolicyNoNotificationChannels{}, res("google_monitoring_alert_policy", "a",
		map[string]ir.Value{"notification_channels": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-238: SCC notification config without streaming
// ---------------------------------------------------------------------------

func TestGCP238(t *testing.T) {
	mustFinding(t, runRule(sccNotificationNoStreaming{}, res("google_scc_notification_config", "n", nil)), "AEGIS-GCP-238")
	mustQuiet(t, runRule(sccNotificationNoStreaming{}, res("google_scc_notification_config", "n",
		map[string]ir.Value{"streaming_config": blks(3, blk("filter", ks("state = \"ACTIVE\"", 4)))})))
	mustQuiet(t, runRule(sccNotificationNoStreaming{}, res("google_scc_notification_config", "n",
		map[string]ir.Value{"streaming_config": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-239: Logging exclusion excludes everything
// ---------------------------------------------------------------------------

func TestGCP239(t *testing.T) {
	mustFinding(t, runRule(logExclusionOverlyBroad{}, res("google_logging_project_exclusion", "e",
		map[string]ir.Value{"filter": ks("", 3)})), "AEGIS-GCP-239")
	mustFinding(t, runRule(logExclusionOverlyBroad{}, res("google_logging_folder_exclusion", "e",
		map[string]ir.Value{"filter": ks("   ", 3)})), "AEGIS-GCP-239")
	mustQuiet(t, runRule(logExclusionOverlyBroad{}, res("google_logging_project_exclusion", "e",
		map[string]ir.Value{"filter": ks("severity < DEFAULT", 3)})))
	mustQuiet(t, runRule(logExclusionOverlyBroad{}, res("google_logging_project_exclusion", "e", nil)))
	mustQuiet(t, runRule(logExclusionOverlyBroad{}, res("google_logging_project_exclusion", "e",
		map[string]ir.Value{"filter": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-240/241: Disabled sink & mute-all
// ---------------------------------------------------------------------------

func TestGCP240_241(t *testing.T) {
	// 240: folder/org/billing sink disabled
	mustFinding(t, runRule(logSinkDisabledNonProject{}, res("google_logging_folder_sink", "s",
		map[string]ir.Value{"disabled": kv(true, 3)})), "AEGIS-GCP-240")
	mustFinding(t, runRule(logSinkDisabledNonProject{}, res("google_logging_organization_sink", "s",
		map[string]ir.Value{"disabled": kv(true, 3)})), "AEGIS-GCP-240")
	mustQuiet(t, runRule(logSinkDisabledNonProject{}, res("google_logging_folder_sink", "s", nil)))
	mustQuiet(t, runRule(logSinkDisabledNonProject{}, res("google_logging_folder_sink", "s",
		map[string]ir.Value{"disabled": kv(false, 3)})))
	mustQuiet(t, runRule(logSinkDisabledNonProject{}, res("google_logging_folder_sink", "s",
		map[string]ir.Value{"disabled": ku(3)})))

	// 241: mute config matching everything
	mustFinding(t, runRule(sccMuteConfigAllFindings{}, res("google_scc_mute_config", "m", nil)), "AEGIS-GCP-241")
	mustFinding(t, runRule(sccMuteConfigAllFindings{}, res("google_scc_mute_config", "m",
		map[string]ir.Value{"filter": ks("", 3)})), "AEGIS-GCP-241")
	mustQuiet(t, runRule(sccMuteConfigAllFindings{}, res("google_scc_mute_config", "m",
		map[string]ir.Value{"filter": ks("severity = \"LOW\"", 3)})))
	mustQuiet(t, runRule(sccMuteConfigAllFindings{}, res("google_scc_mute_config", "m",
		map[string]ir.Value{"filter": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-242/243/244/245/246: Memorystore
// ---------------------------------------------------------------------------

func TestGCP242_246(t *testing.T) {
	// 242: redis without maintenance policy
	mustFinding(t, runRule(redisNoMaintenancePolicy{}, res("google_redis_instance", "r", nil)), "AEGIS-GCP-242")
	mustQuiet(t, runRule(redisNoMaintenancePolicy{}, res("google_redis_instance", "r",
		map[string]ir.Value{"maintenance_policy": blks(3, blk("weekly_maintenance_window",
			blks(4, blk("day", ks("MONDAY", 5)))))})))
	mustQuiet(t, runRule(redisNoMaintenancePolicy{}, res("google_redis_instance", "r",
		map[string]ir.Value{"maintenance_policy": ku(3)})))

	// 243: BASIC tier
	mustFinding(t, runRule(redisTierBasic{}, res("google_redis_instance", "r",
		map[string]ir.Value{"tier": ks("BASIC", 3)})), "AEGIS-GCP-243")
	mustFinding(t, runRule(redisTierBasic{}, res("google_redis_instance", "r", nil)), "AEGIS-GCP-243")
	mustQuiet(t, runRule(redisTierBasic{}, res("google_redis_instance", "r",
		map[string]ir.Value{"tier": ks("STANDARD_HA", 3)})))
	mustQuiet(t, runRule(redisTierBasic{}, res("google_redis_instance", "r",
		map[string]ir.Value{"tier": ku(3)})))

	// 244: direct peering
	mustFinding(t, runRule(redisDirectPeering{}, res("google_redis_instance", "r",
		map[string]ir.Value{"connect_mode": ks("DIRECT_PEERING", 3)})), "AEGIS-GCP-244")
	mustQuiet(t, runRule(redisDirectPeering{}, res("google_redis_instance", "r",
		map[string]ir.Value{"connect_mode": ks("PRIVATE_SERVICE_ACCESS", 3)})))
	mustQuiet(t, runRule(redisDirectPeering{}, res("google_redis_instance", "r", nil)))
	mustQuiet(t, runRule(redisDirectPeering{}, res("google_redis_instance", "r",
		map[string]ir.Value{"connect_mode": ku(3)})))

	// 245: AUTH string in state
	f := mustFinding(t, runRule(redisAuthStringInState{}, res("google_redis_instance", "r",
		map[string]ir.Value{"auth_string": ks("hunter2", 3)})), "AEGIS-GCP-245")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(redisAuthStringInState{}, res("google_redis_instance", "r", nil)))
	mustQuiet(t, runRule(redisAuthStringInState{}, res("google_redis_instance", "r",
		map[string]ir.Value{"auth_string": ku(3)})))

	// 246: memcache without maintenance policy
	mustFinding(t, runRule(memcacheNoMaintenancePolicy{}, res("google_memcache_instance", "m", nil)), "AEGIS-GCP-246")
	mustQuiet(t, runRule(memcacheNoMaintenancePolicy{}, res("google_memcache_instance", "m",
		map[string]ir.Value{"maintenance_policy": blks(3, blk("weekly_maintenance_window",
			blks(4, blk("day", ks("TUESDAY", 5)))))})))
	mustQuiet(t, runRule(memcacheNoMaintenancePolicy{}, res("google_memcache_instance", "m",
		map[string]ir.Value{"maintenance_policy": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-247..251: Spanner instance & database
// ---------------------------------------------------------------------------

func TestGCP247_251(t *testing.T) {
	// 247: automatic backups disabled
	mustFinding(t, runRule(spannerInstanceBackupsDisabled{}, res("google_spanner_instance", "i",
		map[string]ir.Value{"default_backup_schedule_type": ks("NONE", 3)})), "AEGIS-GCP-247")
	mustQuiet(t, runRule(spannerInstanceBackupsDisabled{}, res("google_spanner_instance", "i",
		map[string]ir.Value{"default_backup_schedule_type": ks("AUTOMATIC", 3)})))
	mustQuiet(t, runRule(spannerInstanceBackupsDisabled{}, res("google_spanner_instance", "i", nil)))
	mustQuiet(t, runRule(spannerInstanceBackupsDisabled{}, res("google_spanner_instance", "i",
		map[string]ir.Value{"default_backup_schedule_type": ku(3)})))

	// 248: version retention under 1h
	mustFinding(t, runRule(spannerDBShortVersionRetention{}, res("google_spanner_database", "d",
		map[string]ir.Value{"version_retention_period": ks("1800s", 3)})), "AEGIS-GCP-248")
	mustFinding(t, runRule(spannerDBShortVersionRetention{}, res("google_spanner_database", "d",
		map[string]ir.Value{"version_retention_period": ks("30m", 3)})), "AEGIS-GCP-248")
	mustQuiet(t, runRule(spannerDBShortVersionRetention{}, res("google_spanner_database", "d",
		map[string]ir.Value{"version_retention_period": ks("2h", 3)})))
	mustQuiet(t, runRule(spannerDBShortVersionRetention{}, res("google_spanner_database", "d", nil)))
	mustQuiet(t, runRule(spannerDBShortVersionRetention{}, res("google_spanner_database", "d",
		map[string]ir.Value{"version_retention_period": ku(3)})))
	mustQuiet(t, runRule(spannerDBShortVersionRetention{}, res("google_spanner_database", "d",
		map[string]ir.Value{"version_retention_period": ks("a while", 3)})))

	// 249: no deletion protection
	mustFinding(t, runRule(spannerDBNoDeletionProtection{}, res("google_spanner_database", "d",
		map[string]ir.Value{"deletion_protection": kv(false, 3)})), "AEGIS-GCP-249")
	mustQuiet(t, runRule(spannerDBNoDeletionProtection{}, res("google_spanner_database", "d",
		map[string]ir.Value{"deletion_protection": kv(true, 3)})))
	mustQuiet(t, runRule(spannerDBNoDeletionProtection{}, res("google_spanner_database", "d", nil)))
	mustQuiet(t, runRule(spannerDBNoDeletionProtection{}, res("google_spanner_database", "d",
		map[string]ir.Value{"deletion_protection": ku(3)})))

	// 250: no drop protection
	mustFinding(t, runRule(spannerDBNoDropProtection{}, res("google_spanner_database", "d",
		map[string]ir.Value{"enable_drop_protection": kv(false, 3)})), "AEGIS-GCP-250")
	mustQuiet(t, runRule(spannerDBNoDropProtection{}, res("google_spanner_database", "d",
		map[string]ir.Value{"enable_drop_protection": kv(true, 3)})))
	mustQuiet(t, runRule(spannerDBNoDropProtection{}, res("google_spanner_database", "d", nil)))
	mustQuiet(t, runRule(spannerDBNoDropProtection{}, res("google_spanner_database", "d",
		map[string]ir.Value{"enable_drop_protection": ku(3)})))

	// 251: force destroy
	mustFinding(t, runRule(spannerInstanceForceDestroy{}, res("google_spanner_instance", "i",
		map[string]ir.Value{"force_destroy": kv(true, 3)})), "AEGIS-GCP-251")
	mustQuiet(t, runRule(spannerInstanceForceDestroy{}, res("google_spanner_instance", "i",
		map[string]ir.Value{"force_destroy": kv(false, 3)})))
	mustQuiet(t, runRule(spannerInstanceForceDestroy{}, res("google_spanner_instance", "i", nil)))
	mustQuiet(t, runRule(spannerInstanceForceDestroy{}, res("google_spanner_instance", "i",
		map[string]ir.Value{"force_destroy": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-252/253/254: Firestore
// ---------------------------------------------------------------------------

func TestGCP252_254(t *testing.T) {
	// 252: no CMEK
	mustFinding(t, runRule(firestoreNoCMEK{}, res("google_firestore_database", "f", nil)), "AEGIS-GCP-252")
	mustQuiet(t, runRule(firestoreNoCMEK{}, res("google_firestore_database", "f",
		map[string]ir.Value{"cmek_config": blks(3, blk("kms_key_name", ks("k", 4)))})))
	mustQuiet(t, runRule(firestoreNoCMEK{}, res("google_firestore_database", "f",
		map[string]ir.Value{"cmek_config": ku(3)})))

	// 253: delete protection disabled
	mustFinding(t, runRule(firestoreDeleteProtectionDisabled{}, res("google_firestore_database", "f",
		map[string]ir.Value{"delete_protection_state": ks("DELETE_PROTECTION_DISABLED", 3)})), "AEGIS-GCP-253")
	mustQuiet(t, runRule(firestoreDeleteProtectionDisabled{}, res("google_firestore_database", "f",
		map[string]ir.Value{"delete_protection_state": ks("DELETE_PROTECTION_ENABLED", 3)})))
	mustQuiet(t, runRule(firestoreDeleteProtectionDisabled{}, res("google_firestore_database", "f", nil)))
	mustQuiet(t, runRule(firestoreDeleteProtectionDisabled{}, res("google_firestore_database", "f",
		map[string]ir.Value{"delete_protection_state": ku(3)})))

	// 254: PITR disabled
	f := mustFinding(t, runRule(firestorePITRDisabled{}, res("google_firestore_database", "f",
		map[string]ir.Value{"point_in_time_recovery_enablement": ks("POINT_IN_TIME_RECOVERY_DISABLED", 3)})), "AEGIS-GCP-254")
	if f.Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(firestorePITRDisabled{}, res("google_firestore_database", "f",
		map[string]ir.Value{"point_in_time_recovery_enablement": ks("POINT_IN_TIME_RECOVERY_ENABLED", 3)})))
	mustQuiet(t, runRule(firestorePITRDisabled{}, res("google_firestore_database", "f", nil)))
	mustQuiet(t, runRule(firestorePITRDisabled{}, res("google_firestore_database", "f",
		map[string]ir.Value{"point_in_time_recovery_enablement": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-255/256: Bigtable
// ---------------------------------------------------------------------------

func TestGCP255_256(t *testing.T) {
	// 255: cluster without CMEK
	mustFinding(t, runRule(bigtableClusterNoCMEK{}, res("google_bigtable_instance", "b",
		map[string]ir.Value{"cluster": blks(3, blk("cluster_id", ks("c1", 4), "zone", ks("us-central1-a", 4)))})), "AEGIS-GCP-255")
	mustFinding(t, runRule(bigtableClusterNoCMEK{}, res("google_bigtable_instance", "b",
		map[string]ir.Value{"cluster": blks(3,
			blk("cluster_id", ks("c1", 4), "kms_key_name", ks("k", 4)),
			blk("cluster_id", ks("c2", 4)))})), "AEGIS-GCP-255")
	mustQuiet(t, runRule(bigtableClusterNoCMEK{}, res("google_bigtable_instance", "b",
		map[string]ir.Value{"cluster": blks(3, blk("cluster_id", ks("c1", 4), "kms_key_name", ks("k", 4)))})))
	mustQuiet(t, runRule(bigtableClusterNoCMEK{}, res("google_bigtable_instance", "b", nil)))
	mustQuiet(t, runRule(bigtableClusterNoCMEK{}, res("google_bigtable_instance", "b",
		map[string]ir.Value{"cluster": ku(3)})))

	// 256: no deletion protection
	mustFinding(t, runRule(bigtableNoDeletionProtection{}, res("google_bigtable_instance", "b",
		map[string]ir.Value{"deletion_protection": kv(false, 3)})), "AEGIS-GCP-256")
	mustQuiet(t, runRule(bigtableNoDeletionProtection{}, res("google_bigtable_instance", "b",
		map[string]ir.Value{"deletion_protection": kv(true, 3)})))
	mustQuiet(t, runRule(bigtableNoDeletionProtection{}, res("google_bigtable_instance", "b", nil)))
	mustQuiet(t, runRule(bigtableNoDeletionProtection{}, res("google_bigtable_instance", "b",
		map[string]ir.Value{"deletion_protection": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-257..262: Artifact Registry
// ---------------------------------------------------------------------------

func TestGCP257_262(t *testing.T) {
	// 257: remote repository over plain HTTP
	f := mustFinding(t, runRule(artifactRemoteHTTPRepository{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"remote_repository_config": blks(3, blk("docker_repository",
			blks(4, blk("custom_repository", blks(5, blk("uri", ks("http://mirror.internal/v2/", 6)))))))})), "AEGIS-GCP-257")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(artifactRemoteHTTPRepository{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"remote_repository_config": blks(3, blk("docker_repository",
			blks(4, blk("custom_repository", blks(5, blk("uri", ks("https://mirror.internal/v2/", 6)))))))})))
	mustQuiet(t, runRule(artifactRemoteHTTPRepository{}, res("google_artifact_registry_repository", "a", nil)))
	mustQuiet(t, runRule(artifactRemoteHTTPRepository{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"remote_repository_config": blks(3, blk("docker_repository",
			blks(4, blk("custom_repository", blks(5, blk("uri", ku(6)))))))})))

	// 258: cleanup policies in dry-run
	mustFinding(t, runRule(artifactCleanupPolicyDryRun{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"cleanup_policy_dry_run": kv(true, 3)})), "AEGIS-GCP-258")
	mustQuiet(t, runRule(artifactCleanupPolicyDryRun{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"cleanup_policy_dry_run": kv(false, 3)})))
	mustQuiet(t, runRule(artifactCleanupPolicyDryRun{}, res("google_artifact_registry_repository", "a", nil)))
	mustQuiet(t, runRule(artifactCleanupPolicyDryRun{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"cleanup_policy_dry_run": ku(3)})))

	// 259: mutable Docker tags
	mustFinding(t, runRule(artifactMutableDockerTags{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"format": ks("DOCKER", 3)})), "AEGIS-GCP-259")
	mustFinding(t, runRule(artifactMutableDockerTags{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"format": ks("DOCKER", 3),
			"docker_config": blks(4, blk("immutable_tags", kv(false, 5)))})), "AEGIS-GCP-259")
	mustQuiet(t, runRule(artifactMutableDockerTags{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"format": ks("DOCKER", 3),
			"docker_config": blks(4, blk("immutable_tags", kv(true, 5)))})))
	mustQuiet(t, runRule(artifactMutableDockerTags{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"format": ks("MAVEN", 3)})))
	mustQuiet(t, runRule(artifactMutableDockerTags{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"format": ku(3)})))
	mustQuiet(t, runRule(artifactMutableDockerTags{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"format": ks("DOCKER", 3), "docker_config": ku(4)})))
	mustQuiet(t, runRule(artifactMutableDockerTags{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"format": ks("DOCKER", 3),
			"docker_config": blks(4, blk("immutable_tags", ku(5)))})))

	// 260: repository IAM grants to the public
	f = mustFinding(t, runRule(artifactRepoPublicIAM{}, res("google_artifact_registry_repository_iam_binding", "b",
		map[string]ir.Value{"role": ks("roles/artifactregistry.reader", 3), "members": strList(4, "allUsers")})), "AEGIS-GCP-260")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustFinding(t, runRule(artifactRepoPublicIAM{}, res("google_artifact_registry_repository_iam_member", "m",
		map[string]ir.Value{"role": ks("roles/artifactregistry.writer", 3), "member": ks("allUsers", 4)})), "AEGIS-GCP-260")
	mustQuiet(t, runRule(artifactRepoPublicIAM{}, res("google_artifact_registry_repository_iam_binding", "b",
		map[string]ir.Value{"role": ks("roles/artifactregistry.reader", 3), "members": strList(4, "group:eng@example.com")})))
	mustQuiet(t, runRule(artifactRepoPublicIAM{}, res("google_artifact_registry_repository_iam_member", "m",
		map[string]ir.Value{"role": ks("roles/artifactregistry.reader", 3), "member": ku(4)})))

	// 261: Maven snapshot overwrites
	mustFinding(t, runRule(mavenAllowSnapshotOverwrites{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"maven_config": blks(3, blk("allow_snapshot_overwrites", kv(true, 4)))})), "AEGIS-GCP-261")
	mustQuiet(t, runRule(mavenAllowSnapshotOverwrites{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"maven_config": blks(3, blk("allow_snapshot_overwrites", kv(false, 4)))})))
	mustQuiet(t, runRule(mavenAllowSnapshotOverwrites{}, res("google_artifact_registry_repository", "a", nil)))
	mustQuiet(t, runRule(mavenAllowSnapshotOverwrites{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"maven_config": blks(3, blk("allow_snapshot_overwrites", ku(4)))})))

	// 262: Maven snapshot version policy
	mustFinding(t, runRule(mavenSnapshotVersionPolicy{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"maven_config": blks(3, blk("version_policy", ks("SNAPSHOT", 4)))})), "AEGIS-GCP-262")
	mustQuiet(t, runRule(mavenSnapshotVersionPolicy{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"maven_config": blks(3, blk("version_policy", ks("RELEASE", 4)))})))
	mustQuiet(t, runRule(mavenSnapshotVersionPolicy{}, res("google_artifact_registry_repository", "a", nil)))
	mustQuiet(t, runRule(mavenSnapshotVersionPolicy{}, res("google_artifact_registry_repository", "a",
		map[string]ir.Value{"maven_config": blks(3, blk("version_policy", ku(4)))})))
}
