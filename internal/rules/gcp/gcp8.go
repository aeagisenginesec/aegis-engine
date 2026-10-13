// Package gcp — expansion round 8 (AEGIS-GCP-223..262).
//
// Covers KMS / Secret Manager, Logging / Monitoring, Memorystore,
// Spanner / Firestore / Bigtable, and Artifact Registry.
//
// Absent-attribute policy for this file: an absent attribute yields a
// finding only when the provider default is the insecure one (key ring
// location defaults to global, Redis tier defaults to BASIC, Redis
// maintenance policy has no default). Present-but-unresolved values
// yield NO finding, per the unknown-value contract.
//
// Several candidate checks from the round brief already exist in the
// pack and were deliberately NOT duplicated here:
//   - KMS rotation absent / >90d            -> AEGIS-GCP-012 / 081
//   - KMS crypto-key IAM grants to public -> AEGIS-GCP-082 (also covers key-ring IAM)
//   - Secret Manager replication CMEK     -> AEGIS-GCP-138
//   - Secret Manager rotation absent       -> AEGIS-GCP-022
//   - Log sink unique_writer_identity      -> AEGIS-GCP-085
//   - Monitoring alert policy disabled     -> AEGIS-GCP-141
//   - Artifact Registry CMEK / cleanup     -> AEGIS-GCP-127 / 128
//
// Two deviations from the brief, both tightening accuracy:
//   - Log-bucket CMEK is checked via cmek_settings.kms_key_name
//     (nestedCMEK), not a top-level kms_key_name attribute, which the
//     google_logging_project_bucket_config resource does not have.
//   - Bigtable CMEK is checked per cluster block (clusters[].kms_key_name),
//     because a top-level attribute does not exist and a single
//     unencrypted cluster is still a finding.
//   - Spanner "instance CMEK" was replaced: google_spanner_instance has no
//     CMEK attribute (encryption is per-database, covered by AEGIS-GCP-126);
//     the slot now flags default_backup_schedule_type = "NONE".
//   - "Secret rotation_period > 90d" was listed as skip/covered, but no
//     existing rule covers it for secrets (AEGIS-GCP-081 is KMS-only);
//     it is included as AEGIS-GCP-231.
package gcp

import (
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// GCP8Rules returns GCP expansion rules 223..262 in ID order.
func GCP8Rules() []ir.Rule {
	return []ir.Rule{
		kmsKeyRingGlobalLocation{},          // AEGIS-GCP-223
		kmsShortDestroyDuration{},           // AEGIS-GCP-224
		kmsSoftwareProtectionLevel{},        // AEGIS-GCP-225
		secretManagerPublicIAM{},            // AEGIS-GCP-226
		secretDataInState{},                 // AEGIS-GCP-227
		secretAutomaticReplication{},        // AEGIS-GCP-228
		secretSingleRegionReplication{},     // AEGIS-GCP-229
		secretRotationMissingPeriod{},       // AEGIS-GCP-230
		secretLongRotationPeriod{},          // AEGIS-GCP-231
		logSinkSeverityExclusion{},          // AEGIS-GCP-232
		logBucketNoLockedRetention{},        // AEGIS-GCP-233
		logBucketNoCMEK{},                   // AEGIS-GCP-234
		logBucketShortRetention{},           // AEGIS-GCP-235
		logBucketRetentionUnlocked{},        // AEGIS-GCP-236
		alertPolicyNoNotificationChannels{}, // AEGIS-GCP-237
		sccNotificationNoStreaming{},        // AEGIS-GCP-238
		logExclusionOverlyBroad{},           // AEGIS-GCP-239
		logSinkDisabledNonProject{},         // AEGIS-GCP-240
		sccMuteConfigAllFindings{},          // AEGIS-GCP-241
		redisNoMaintenancePolicy{},          // AEGIS-GCP-242
		redisTierBasic{},                    // AEGIS-GCP-243
		redisDirectPeering{},                // AEGIS-GCP-244
		redisAuthStringInState{},            // AEGIS-GCP-245
		memcacheNoMaintenancePolicy{},       // AEGIS-GCP-246
		spannerInstanceBackupsDisabled{},    // AEGIS-GCP-247
		spannerDBShortVersionRetention{},    // AEGIS-GCP-248
		spannerDBNoDeletionProtection{},     // AEGIS-GCP-249
		spannerDBNoDropProtection{},         // AEGIS-GCP-250
		spannerInstanceForceDestroy{},       // AEGIS-GCP-251
		firestoreNoCMEK{},                   // AEGIS-GCP-252
		firestoreDeleteProtectionDisabled{}, // AEGIS-GCP-253
		firestorePITRDisabled{},             // AEGIS-GCP-254
		bigtableClusterNoCMEK{},             // AEGIS-GCP-255
		bigtableNoDeletionProtection{},      // AEGIS-GCP-256
		artifactRemoteHTTPRepository{},      // AEGIS-GCP-257
		artifactCleanupPolicyDryRun{},       // AEGIS-GCP-258
		artifactMutableDockerTags{},         // AEGIS-GCP-259
		artifactRepoPublicIAM{},             // AEGIS-GCP-260
		mavenAllowSnapshotOverwrites{},      // AEGIS-GCP-261
		mavenSnapshotVersionPolicy{},        // AEGIS-GCP-262
	}
}

// parseDurationHMS parses GCP-style durations ("86400s", "60m", "1h") to
// seconds. ok=false when the value is absent-shaped or unparseable.
func parseDurationHMS(v string) (secs int64, ok bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return 0, false
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(v, "s"):
		v = strings.TrimSuffix(v, "s")
	case strings.HasSuffix(v, "m"):
		v = strings.TrimSuffix(v, "m")
		mult = 60
	case strings.HasSuffix(v, "h"):
		v = strings.TrimSuffix(v, "h")
		mult = 3600
	default:
		return 0, false
	}
	if v == "" {
		return 0, false
	}
	var n int64
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n * mult, true
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-223: KMS key ring in the global location
// ---------------------------------------------------------------------------

type kmsKeyRingGlobalLocation struct{}

func (kmsKeyRingGlobalLocation) ID() string { return "AEGIS-GCP-223" }
func (kmsKeyRingGlobalLocation) Title() string {
	return "KMS key ring in the global location"
}
func (kmsKeyRingGlobalLocation) Description() string {
	return "google_kms_key_ring with location = \"global\" (the provider " +
		"default) places key material under multi-region control instead " +
		"of a single region. Pin the key ring to a regional location for " +
		"data-residency control."
}
func (kmsKeyRingGlobalLocation) Severity() ir.Severity { return ir.SeverityLow }

func (kmsKeyRingGlobalLocation) AppliesTo(resType string) bool {
	return resType == "google_kms_key_ring"
}

func (s kmsKeyRingGlobalLocation) Check(r ir.Resource) []ir.Finding {
	loc, span, present, known := getString(r, "location")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || strings.EqualFold(strings.TrimSpace(loc), "global") {
		actual := "global"
		if !present {
			actual = "absent (provider default: global)"
		}
		return []ir.Finding{mkFinding(s, r, "location",
			evidenceSpan(span, r.Span), actual, "location = \"<region>\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-224: KMS crypto key with very short destroy-scheduled duration
// ---------------------------------------------------------------------------

type kmsShortDestroyDuration struct{}

func (kmsShortDestroyDuration) ID() string { return "AEGIS-GCP-224" }
func (kmsShortDestroyDuration) Title() string {
	return "KMS crypto key with very short destroy-scheduled duration"
}
func (kmsShortDestroyDuration) Description() string {
	return "google_kms_crypto_key with destroy_scheduled_duration under " +
		"24h (86400s) leaves almost no cooling-off window to cancel an " +
		"accidental or malicious key destruction. Keep at least 24h."
}
func (kmsShortDestroyDuration) Severity() ir.Severity { return ir.SeverityLow }

func (kmsShortDestroyDuration) AppliesTo(resType string) bool {
	return resType == "google_kms_crypto_key"
}

func (s kmsShortDestroyDuration) Check(r ir.Resource) []ir.Finding {
	dur, span, present, known := getString(r, "destroy_scheduled_duration")
	if !present || !known {
		return nil // absent (default 24h is fine) or unresolved
	}
	secs := parseDurationSeconds(dur)
	if secs < 0 {
		return nil // unparseable: cannot decide
	}
	if secs < 86400 {
		// An empty value parses as 0s: keep firing, but report a
		// non-empty Actual so the evidence is meaningful.
		actual := dur
		if actual == "" {
			actual = "(empty — parses as 0s)"
		}
		return []ir.Finding{mkFinding(s, r, "destroy_scheduled_duration", span,
			actual, "destroy_scheduled_duration >= \"86400s\" (24h)")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-225: KMS crypto key with software protection level
// ---------------------------------------------------------------------------

type kmsSoftwareProtectionLevel struct{}

func (kmsSoftwareProtectionLevel) ID() string { return "AEGIS-GCP-225" }
func (kmsSoftwareProtectionLevel) Title() string {
	return "KMS crypto key with software protection level"
}
func (kmsSoftwareProtectionLevel) Description() string {
	return "google_kms_crypto_key with version_template.protection_level = " +
		"\"SOFTWARE\" keeps key material in software instead of a " +
		"hardware security module. Use HSM protection for high-value keys."
}
func (kmsSoftwareProtectionLevel) Severity() ir.Severity { return ir.SeverityMedium }

func (kmsSoftwareProtectionLevel) AppliesTo(resType string) bool {
	return resType == "google_kms_crypto_key"
}

func (s kmsSoftwareProtectionLevel) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "version_template")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		lvl, lspan, lpresent, lknown := blockString(b, "protection_level")
		if lpresent && !lknown {
			return nil // unresolved: cannot decide
		}
		if lpresent && strings.EqualFold(strings.TrimSpace(lvl), "SOFTWARE") {
			return []ir.Finding{mkFinding(s, r, "version_template.protection_level",
				evidenceSpan(lspan, span), lvl, "protection_level = \"HSM\"")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-226: Secret Manager secret IAM grants to the public
// ---------------------------------------------------------------------------

type secretManagerPublicIAM struct{}

func (secretManagerPublicIAM) ID() string { return "AEGIS-GCP-226" }
func (secretManagerPublicIAM) Title() string {
	return "Secret Manager secret IAM grants to the public"
}
func (secretManagerPublicIAM) Description() string {
	return "google_secret_manager_secret_iam_binding/member granting any " +
		"role to allUsers or allAuthenticatedUsers exposes secret metadata " +
		"or values to the internet. Remove public members."
}
func (secretManagerPublicIAM) Severity() ir.Severity { return ir.SeverityCritical }

func (secretManagerPublicIAM) AppliesTo(resType string) bool {
	return resType == "google_secret_manager_secret_iam_binding" ||
		resType == "google_secret_manager_secret_iam_member"
}

func (s secretManagerPublicIAM) Check(r ir.Resource) []ir.Finding {
	switch r.Type {
	case "google_secret_manager_secret_iam_binding":
		members, span, ok := getStringList(r, "members")
		if !ok {
			return nil // members absent or unresolved: cannot decide
		}
		for _, m := range members {
			if isPublicMember(m) {
				return []ir.Finding{mkFinding(s, r, "members", span,
					m, "remove allUsers/allAuthenticatedUsers from the binding")}
			}
		}
		return nil
	case "google_secret_manager_secret_iam_member":
		member, span, present, known := getString(r, "member")
		if !present || !known {
			return nil
		}
		if isPublicMember(member) {
			return []ir.Finding{mkFinding(s, r, "member", span,
				member, "remove allUsers/allAuthenticatedUsers from the member")}
		}
		return nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-227: Secret Manager secret value in Terraform state
// ---------------------------------------------------------------------------

type secretDataInState struct{}

func (secretDataInState) ID() string { return "AEGIS-GCP-227" }
func (secretDataInState) Title() string {
	return "Secret Manager secret value in Terraform state"
}
func (secretDataInState) Description() string {
	return "google_secret_manager_secret_version with secret_data set " +
		"stores the plaintext secret value in Terraform state. Manage " +
		"secret values outside Terraform (write-only or external flow)."
}
func (secretDataInState) Severity() ir.Severity { return ir.SeverityHigh }

func (secretDataInState) AppliesTo(resType string) bool {
	return resType == "google_secret_manager_secret_version"
}

func (s secretDataInState) Check(r ir.Resource) []ir.Finding {
	data, span, present, known := getString(r, "secret_data")
	if !present || !known {
		return nil
	}
	if strings.TrimSpace(data) == "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "secret_data", span,
		"(plaintext secret value in state)", "manage the secret value outside Terraform")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-228: Secret Manager secret with automatic replication
// ---------------------------------------------------------------------------

type secretAutomaticReplication struct{}

func (secretAutomaticReplication) ID() string { return "AEGIS-GCP-228" }
func (secretAutomaticReplication) Title() string {
	return "Secret Manager secret with automatic replication"
}
func (secretAutomaticReplication) Description() string {
	return "google_secret_manager_secret with replication.automatic " +
		"covers replication placement to Google instead of pinning regions " +
		"with user_managed replication. Prefer user_managed replication " +
		"for placement control."
}
func (secretAutomaticReplication) Severity() ir.Severity { return ir.SeverityLow }

func (secretAutomaticReplication) AppliesTo(resType string) bool {
	return resType == "google_secret_manager_secret"
}

func (s secretAutomaticReplication) Check(r ir.Resource) []ir.Finding {
	rep, span, present, known := getBlocks(r, "replication")
	if !present || !known {
		return nil
	}
	for _, rb := range rep {
		v, ok := rb["automatic"]
		if !ok {
			continue
		}
		if !v.Known {
			return nil // unresolved: cannot decide
		}
		// Present in any shape (empty block included): automatic replication.
		return []ir.Finding{mkFinding(s, r, "replication",
			evidenceSpan(span, r.Span), "replication.automatic in use",
			"replication { user_managed { replicas { location = \"...\" } } }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-229: Secret Manager secret replicated to a single region
// ---------------------------------------------------------------------------

type secretSingleRegionReplication struct{}

func (secretSingleRegionReplication) ID() string { return "AEGIS-GCP-229" }
func (secretSingleRegionReplication) Title() string {
	return "Secret Manager secret replicated to a single region"
}
func (secretSingleRegionReplication) Description() string {
	return "google_secret_manager_secret with user_managed replication to " +
		"a single replica region has no regional redundancy for the " +
		"secret. Replicate to at least two regions."
}
func (secretSingleRegionReplication) Severity() ir.Severity { return ir.SeverityLow }

func (secretSingleRegionReplication) AppliesTo(resType string) bool {
	return resType == "google_secret_manager_secret"
}

func (s secretSingleRegionReplication) Check(r ir.Resource) []ir.Finding {
	rep, span, present, known := getBlocks(r, "replication")
	if !present || !known {
		return nil
	}
	for _, rb := range rep {
		for _, um := range blockList(rb, "user_managed") {
			if len(blockList(um, "replicas")) == 1 {
				return []ir.Finding{mkFinding(s, r, "replication",
					evidenceSpan(span, r.Span),
					"user_managed replication with a single replica",
					"replicas in at least two regions")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-230: Secret Manager rotation block without rotation period
// ---------------------------------------------------------------------------

type secretRotationMissingPeriod struct{}

func (secretRotationMissingPeriod) ID() string { return "AEGIS-GCP-230" }
func (secretRotationMissingPeriod) Title() string {
	return "Secret Manager rotation block without rotation period"
}
func (secretRotationMissingPeriod) Description() string {
	return "google_secret_manager_secret with a rotation block but no " +
		"rotation_period never actually rotates. Set rotation_period " +
		"(e.g. 7776000s for 90 days)."
}
func (secretRotationMissingPeriod) Severity() ir.Severity { return ir.SeverityLow }

func (secretRotationMissingPeriod) AppliesTo(resType string) bool {
	return resType == "google_secret_manager_secret"
}

func (s secretRotationMissingPeriod) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "rotation")
	if !present || !known || len(blks) == 0 {
		return nil // absent rotation is AEGIS-GCP-022's scope
	}
	for _, b := range blks {
		p, _, ppresent, pknown := blockString(b, "rotation_period")
		if ppresent && !pknown {
			return nil // unresolved: cannot decide
		}
		if ppresent && strings.TrimSpace(p) != "" {
			return nil // rotation period configured
		}
	}
	return []ir.Finding{mkFinding(s, r, "rotation",
		evidenceSpan(span, r.Span), "rotation block without rotation_period",
		"rotation { rotation_period = \"7776000s\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-231: Secret Manager secret with rotation period over 90 days
// ---------------------------------------------------------------------------

type secretLongRotationPeriod struct{}

func (secretLongRotationPeriod) ID() string { return "AEGIS-GCP-231" }
func (secretLongRotationPeriod) Title() string {
	return "Secret Manager secret with rotation period over 90 days"
}
func (secretLongRotationPeriod) Description() string {
	return "google_secret_manager_secret with rotation.rotation_period " +
		"longer than 7776000s (90 days) rotates too infrequently. " +
		"Rotate secrets at least every 90 days."
}
func (secretLongRotationPeriod) Severity() ir.Severity { return ir.SeverityLow }

func (secretLongRotationPeriod) AppliesTo(resType string) bool {
	return resType == "google_secret_manager_secret"
}

func (s secretLongRotationPeriod) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "rotation")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		p, pspan, ppresent, pknown := blockString(b, "rotation_period")
		if !ppresent || !pknown {
			continue // AEGIS-GCP-230's scope or unresolved
		}
		secs := parseDurationSeconds(p)
		if secs < 0 {
			continue // unparseable: cannot decide
		}
		if secs > 7776000 {
			return []ir.Finding{mkFinding(s, r, "rotation.rotation_period",
				evidenceSpan(pspan, span), p,
				"rotation_period <= \"7776000s\" (90 days)")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-232: Logging sink filter excludes security logs
// ---------------------------------------------------------------------------

type logSinkSeverityExclusion struct{}

func (logSinkSeverityExclusion) ID() string { return "AEGIS-GCP-232" }
func (logSinkSeverityExclusion) Title() string {
	return "Logging sink filter excludes security logs"
}
func (logSinkSeverityExclusion) Description() string {
	return "A logging sink whose filter excludes entries below a severity " +
		"(e.g. severity < WARNING) drops warning-level security events " +
		"from the export, blinding detection on the sink destination."
}
func (logSinkSeverityExclusion) Severity() ir.Severity { return ir.SeverityMedium }

func (logSinkSeverityExclusion) AppliesTo(resType string) bool {
	return resType == "google_logging_project_sink" ||
		resType == "google_logging_folder_sink"
}

func (s logSinkSeverityExclusion) Check(r ir.Resource) []ir.Finding {
	filter, span, present, known := getString(r, "filter")
	if !present || !known {
		return nil
	}
	norm := strings.ReplaceAll(strings.ToLower(filter), " ", "")
	if strings.Contains(norm, "severity<") || strings.Contains(norm, "severity!=") {
		return []ir.Finding{mkFinding(s, r, "filter", span, filter,
			"filter without severity exclusions (e.g. severity >= WARNING)")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-233: Log bucket without retention days
// ---------------------------------------------------------------------------

type logBucketNoLockedRetention struct{}

func (logBucketNoLockedRetention) ID() string { return "AEGIS-GCP-233" }
func (logBucketNoLockedRetention) Title() string {
	return "Log bucket without retention or unlocked retention"
}
func (logBucketNoLockedRetention) Description() string {
	return "google_logging_project_bucket_config without retention_days " +
		"keeps logs only for the short default window, and retention " +
		"with locked = false can later be shortened. Set retention_days " +
		"with locked = true for tamper-resistant audit retention."
}
func (logBucketNoLockedRetention) Severity() ir.Severity { return ir.SeverityMedium }

func (logBucketNoLockedRetention) AppliesTo(resType string) bool {
	return resType == "google_logging_project_bucket_config"
}

func (s logBucketNoLockedRetention) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getNum(r, "retention_days")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "retention_days",
			evidenceSpan(span, r.Span), "absent (short default retention)",
			"retention_days = 30 with locked = true")}
	}
	locked, lspan, lpresent, lknown := getBool(r, "locked")
	if lpresent && !lknown {
		return nil
	}
	if lpresent && !locked {
		return []ir.Finding{mkFinding(s, r, "locked",
			evidenceSpan(lspan, r.Span), "false", "locked = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-234: Log bucket without CMEK
// ---------------------------------------------------------------------------

type logBucketNoCMEK struct{}

func (logBucketNoCMEK) ID() string { return "AEGIS-GCP-234" }
func (logBucketNoCMEK) Title() string {
	return "Log bucket without customer-managed encryption"
}
func (logBucketNoCMEK) Description() string {
	return "google_logging_project_bucket_config without " +
		"cmek_settings.kms_key_name relies on Google-managed keys for " +
		"stored logs. Assign a customer-managed Cloud KMS key."
}
func (logBucketNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (logBucketNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_logging_project_bucket_config"
}

func (s logBucketNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"cmek_settings"}, "kms_key_name", "cmek_settings")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-235: Log bucket with very short retention
// ---------------------------------------------------------------------------

type logBucketShortRetention struct{}

func (logBucketShortRetention) ID() string { return "AEGIS-GCP-235" }
func (logBucketShortRetention) Title() string {
	return "Log bucket with retention under 30 days"
}
func (logBucketShortRetention) Description() string {
	return "google_logging_project_bucket_config with retention_days " +
		"under 30 keeps too little audit history for incident response. " +
		"Retain logs for at least 30 days."
}
func (logBucketShortRetention) Severity() ir.Severity { return ir.SeverityLow }

func (logBucketShortRetention) AppliesTo(resType string) bool {
	return resType == "google_logging_project_bucket_config"
}

func (s logBucketShortRetention) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNum(r, "retention_days")
	if !present || !known {
		return nil
	}
	if days >= 0 && days < 30 {
		return []ir.Finding{mkFinding(s, r, "retention_days", span,
			strings.TrimRight(strings.TrimRight(floatToStr(days), "0"), "."),
			"retention_days >= 30")}
	}
	return nil
}

// floatToStr renders a float without exponent notation.
func floatToStr(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-236: Log bucket retention not locked
// ---------------------------------------------------------------------------

type logBucketRetentionUnlocked struct{}

func (logBucketRetentionUnlocked) ID() string { return "AEGIS-GCP-236" }
func (logBucketRetentionUnlocked) Title() string {
	return "Log bucket retention not locked"
}
func (logBucketRetentionUnlocked) Description() string {
	return "google_logging_project_bucket_config with retention_days set " +
		"but locked not true allows the retention window to be shortened " +
		"later, silently trimming the audit trail. Lock the retention."
}
func (logBucketRetentionUnlocked) Severity() ir.Severity { return ir.SeverityLow }

func (logBucketRetentionUnlocked) AppliesTo(resType string) bool {
	return resType == "google_logging_project_bucket_config"
}

func (s logBucketRetentionUnlocked) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getNum(r, "retention_days")
	if !present || !known {
		return nil // AEGIS-GCP-233's scope or unresolved
	}
	_, lspan, lpresent, lknown := getBool(r, "locked")
	if lpresent && !lknown {
		return nil
	}
	if !lpresent {
		return []ir.Finding{mkFinding(s, r, "locked",
			evidenceSpan(lspan, r.Span), "absent (retention can be shortened)",
			"locked = true")}
	}
	return nil // locked true, or explicit false (AEGIS-GCP-233's scope)
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-237: Monitoring alert policy without notification channels
// ---------------------------------------------------------------------------

type alertPolicyNoNotificationChannels struct{}

func (alertPolicyNoNotificationChannels) ID() string { return "AEGIS-GCP-237" }
func (alertPolicyNoNotificationChannels) Title() string {
	return "Monitoring alert policy without notification channels"
}
func (alertPolicyNoNotificationChannels) Description() string {
	return "google_monitoring_alert_policy without notification_channels " +
		"fires alerts that nobody receives. Attach at least one " +
		"notification channel so incidents reach responders."
}
func (alertPolicyNoNotificationChannels) Severity() ir.Severity { return ir.SeverityLow }

func (alertPolicyNoNotificationChannels) AppliesTo(resType string) bool {
	return resType == "google_monitoring_alert_policy"
}

func (s alertPolicyNoNotificationChannels) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["notification_channels"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "notification_channels",
			evidenceSpan(ir.Span{}, r.Span), "absent (alerts go nowhere)",
			"notification_channels = [...]")}
	}
	if !v.Known {
		return nil
	}
	channels, _, ok := getStringList(r, "notification_channels")
	if !ok {
		return nil // unexpected shape: cannot decide
	}
	if len(channels) == 0 {
		return []ir.Finding{mkFinding(s, r, "notification_channels", v.Span,
			"empty (alerts go nowhere)", "notification_channels = [...]")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-238: SCC notification config without streaming
// ---------------------------------------------------------------------------

type sccNotificationNoStreaming struct{}

func (sccNotificationNoStreaming) ID() string { return "AEGIS-GCP-238" }
func (sccNotificationNoStreaming) Title() string {
	return "SCC notification config without streaming"
}
func (sccNotificationNoStreaming) Description() string {
	return "google_scc_notification_config without streaming_config only " +
		"delivers findings in batch, delaying response to new Security " +
		"Command Center findings. Enable streaming_config for continuous " +
		"delivery."
}
func (sccNotificationNoStreaming) Severity() ir.Severity { return ir.SeverityLow }

func (sccNotificationNoStreaming) AppliesTo(resType string) bool {
	return resType == "google_scc_notification_config"
}

func (s sccNotificationNoStreaming) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "streaming_config")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "streaming_config",
		evidenceSpan(span, r.Span), "absent (batch delivery only)",
		"streaming_config { filter = \"...\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-239: Logging exclusion excludes everything
// ---------------------------------------------------------------------------

type logExclusionOverlyBroad struct{}

func (logExclusionOverlyBroad) ID() string { return "AEGIS-GCP-239" }
func (logExclusionOverlyBroad) Title() string {
	return "Logging exclusion excludes everything"
}
func (logExclusionOverlyBroad) Description() string {
	return "A logging exclusion with an empty filter drops every log " +
		"entry, silently discarding the audit trail it was meant to trim. " +
		"Narrow the filter or remove the exclusion."
}
func (logExclusionOverlyBroad) Severity() ir.Severity { return ir.SeverityMedium }

func (logExclusionOverlyBroad) AppliesTo(resType string) bool {
	return resType == "google_logging_project_exclusion" ||
		resType == "google_logging_folder_exclusion"
}

func (s logExclusionOverlyBroad) Check(r ir.Resource) []ir.Finding {
	filter, span, present, known := getString(r, "filter")
	if !present || !known {
		return nil
	}
	if strings.TrimSpace(filter) == "" {
		return []ir.Finding{mkFinding(s, r, "filter", span,
			"\"\" (excludes every log entry)",
			"filter = \"<narrow exclusion filter>\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-240: Non-project logging sink disabled
// ---------------------------------------------------------------------------

type logSinkDisabledNonProject struct{}

func (logSinkDisabledNonProject) ID() string { return "AEGIS-GCP-240" }
func (logSinkDisabledNonProject) Title() string {
	return "Folder/organization/billing logging sink disabled"
}
func (logSinkDisabledNonProject) Description() string {
	return "A folder, organization, or billing-account logging sink with " +
		"disabled = true stops the export of audit logs, silently " +
		"dropping the audit trail. Keep sinks enabled."
}
func (logSinkDisabledNonProject) Severity() ir.Severity { return ir.SeverityMedium }

func (logSinkDisabledNonProject) AppliesTo(resType string) bool {
	return resType == "google_logging_folder_sink" ||
		resType == "google_logging_organization_sink" ||
		resType == "google_logging_billing_account_sink"
}

func (s logSinkDisabledNonProject) Check(r ir.Resource) []ir.Finding {
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
// AEGIS-GCP-241: SCC mute config mutes all findings
// ---------------------------------------------------------------------------

type sccMuteConfigAllFindings struct{}

func (sccMuteConfigAllFindings) ID() string { return "AEGIS-GCP-241" }
func (sccMuteConfigAllFindings) Title() string {
	return "SCC mute config mutes all findings"
}
func (sccMuteConfigAllFindings) Description() string {
	return "google_scc_mute_config with an absent or empty filter mutes " +
		"every Security Command Center finding, hiding real threats. " +
		"Scope mute configs with a narrow filter."
}
func (sccMuteConfigAllFindings) Severity() ir.Severity { return ir.SeverityMedium }

func (sccMuteConfigAllFindings) AppliesTo(resType string) bool {
	return resType == "google_scc_mute_config"
}

func (s sccMuteConfigAllFindings) Check(r ir.Resource) []ir.Finding {
	filter, span, present, known := getString(r, "filter")
	if present && !known {
		return nil
	}
	if !present || strings.TrimSpace(filter) == "" {
		actual := "absent (matches every finding)"
		if present {
			actual = "\"\" (matches every finding)"
		}
		return []ir.Finding{mkFinding(s, r, "filter",
			evidenceSpan(span, r.Span), actual,
			"filter = \"<narrow mute filter>\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-242: Memorystore Redis without maintenance policy
// ---------------------------------------------------------------------------

type redisNoMaintenancePolicy struct{}

func (redisNoMaintenancePolicy) ID() string { return "AEGIS-GCP-242" }
func (redisNoMaintenancePolicy) Title() string {
	return "Memorystore Redis without maintenance policy"
}
func (redisNoMaintenancePolicy) Description() string {
	return "google_redis_instance without maintenance_policy lets Google " +
		"apply maintenance at any time, risking unplanned disruption. " +
		"Define a weekly maintenance window."
}
func (redisNoMaintenancePolicy) Severity() ir.Severity { return ir.SeverityLow }

func (redisNoMaintenancePolicy) AppliesTo(resType string) bool {
	return resType == "google_redis_instance"
}

func (s redisNoMaintenancePolicy) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "maintenance_policy")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "maintenance_policy",
		evidenceSpan(span, r.Span), "absent (uncontrolled maintenance)",
		"maintenance_policy { weekly_maintenance_window { ... } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-243: Memorystore Redis on the BASIC tier
// ---------------------------------------------------------------------------

type redisTierBasic struct{}

func (redisTierBasic) ID() string { return "AEGIS-GCP-243" }
func (redisTierBasic) Title() string {
	return "Memorystore Redis on the BASIC tier without HA"
}
func (redisTierBasic) Description() string {
	return "google_redis_instance with tier = \"BASIC\" (the provider " +
		"default) runs a single node with no high-availability replica. " +
		"Use STANDARD_HA for production workloads."
}
func (redisTierBasic) Severity() ir.Severity { return ir.SeverityLow }

func (redisTierBasic) AppliesTo(resType string) bool {
	return resType == "google_redis_instance"
}

func (s redisTierBasic) Check(r ir.Resource) []ir.Finding {
	tier, span, present, known := getString(r, "tier")
	if present && !known {
		return nil
	}
	if !present || strings.EqualFold(strings.TrimSpace(tier), "BASIC") {
		actual := "BASIC"
		if !present {
			actual = "absent (provider default: BASIC)"
		}
		return []ir.Finding{mkFinding(s, r, "tier",
			evidenceSpan(span, r.Span), actual, "tier = \"STANDARD_HA\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-244: Memorystore Redis with direct peering connectivity
// ---------------------------------------------------------------------------

type redisDirectPeering struct{}

func (redisDirectPeering) ID() string { return "AEGIS-GCP-244" }
func (redisDirectPeering) Title() string {
	return "Memorystore Redis with direct peering connectivity"
}
func (redisDirectPeering) Description() string {
	return "google_redis_instance with connect_mode = \"DIRECT_PEERING\" " +
		"exposes the instance over VPC peering instead of isolating it " +
		"behind Private Service Access. Use connect_mode = " +
		"\"PRIVATE_SERVICE_ACCESS\"."
}
func (redisDirectPeering) Severity() ir.Severity { return ir.SeverityMedium }

func (redisDirectPeering) AppliesTo(resType string) bool {
	return resType == "google_redis_instance"
}

func (s redisDirectPeering) Check(r ir.Resource) []ir.Finding {
	mode, span, present, known := getString(r, "connect_mode")
	if !present || !known {
		return nil // only explicit DIRECT_PEERING fires
	}
	if strings.EqualFold(strings.TrimSpace(mode), "DIRECT_PEERING") {
		return []ir.Finding{mkFinding(s, r, "connect_mode", span, mode,
			"connect_mode = \"PRIVATE_SERVICE_ACCESS\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-245: Memorystore Redis AUTH string in Terraform state
// ---------------------------------------------------------------------------

type redisAuthStringInState struct{}

func (redisAuthStringInState) ID() string { return "AEGIS-GCP-245" }
func (redisAuthStringInState) Title() string {
	return "Memorystore Redis AUTH string in Terraform state"
}
func (redisAuthStringInState) Description() string {
	return "google_redis_instance with auth_string set stores the Redis " +
		"AUTH password in plaintext in Terraform state. Let the provider " +
		"generate the password and read it from the instance instead."
}
func (redisAuthStringInState) Severity() ir.Severity { return ir.SeverityHigh }

func (redisAuthStringInState) AppliesTo(resType string) bool {
	return resType == "google_redis_instance"
}

func (s redisAuthStringInState) Check(r ir.Resource) []ir.Finding {
	auth, span, present, known := getString(r, "auth_string")
	if !present || !known {
		return nil
	}
	if strings.TrimSpace(auth) == "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "auth_string", span,
		"(plaintext AUTH password in state)",
		"omit auth_string; use the generated password")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-246: Memorystore Memcached without maintenance policy
// ---------------------------------------------------------------------------

type memcacheNoMaintenancePolicy struct{}

func (memcacheNoMaintenancePolicy) ID() string { return "AEGIS-GCP-246" }
func (memcacheNoMaintenancePolicy) Title() string {
	return "Memorystore Memcached without maintenance policy"
}
func (memcacheNoMaintenancePolicy) Description() string {
	return "google_memcache_instance without maintenance_policy lets " +
		"Google apply maintenance at any time, risking unplanned " +
		"disruption. Define a weekly maintenance window."
}
func (memcacheNoMaintenancePolicy) Severity() ir.Severity { return ir.SeverityLow }

func (memcacheNoMaintenancePolicy) AppliesTo(resType string) bool {
	return resType == "google_memcache_instance"
}

func (s memcacheNoMaintenancePolicy) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "maintenance_policy")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "maintenance_policy",
		evidenceSpan(span, r.Span), "absent (uncontrolled maintenance)",
		"maintenance_policy { weekly_maintenance_window { ... } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-247: Spanner instance with automatic backups disabled
// ---------------------------------------------------------------------------

type spannerInstanceBackupsDisabled struct{}

func (spannerInstanceBackupsDisabled) ID() string { return "AEGIS-GCP-247" }
func (spannerInstanceBackupsDisabled) Title() string {
	return "Spanner instance with automatic backups disabled"
}
func (spannerInstanceBackupsDisabled) Description() string {
	return "google_spanner_instance with default_backup_schedule_type = " +
		"\"NONE\" creates no automatic backups, leaving data without a " +
		"recovery path. Use default_backup_schedule_type = \"AUTOMATIC\"."
}
func (spannerInstanceBackupsDisabled) Severity() ir.Severity { return ir.SeverityMedium }

func (spannerInstanceBackupsDisabled) AppliesTo(resType string) bool {
	return resType == "google_spanner_instance"
}

func (s spannerInstanceBackupsDisabled) Check(r ir.Resource) []ir.Finding {
	t, span, present, known := getString(r, "default_backup_schedule_type")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(t), "NONE") {
		return []ir.Finding{mkFinding(s, r, "default_backup_schedule_type", span,
			t, "default_backup_schedule_type = \"AUTOMATIC\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-248: Spanner database with very short version retention
// ---------------------------------------------------------------------------

type spannerDBShortVersionRetention struct{}

func (spannerDBShortVersionRetention) ID() string { return "AEGIS-GCP-248" }
func (spannerDBShortVersionRetention) Title() string {
	return "Spanner database with version retention under 1 hour"
}
func (spannerDBShortVersionRetention) Description() string {
	return "google_spanner_database with version_retention_period under " +
		"1h (3600s) keeps too little history for point-in-time recovery. " +
		"Retain versions for at least 1 hour."
}
func (spannerDBShortVersionRetention) Severity() ir.Severity { return ir.SeverityLow }

func (spannerDBShortVersionRetention) AppliesTo(resType string) bool {
	return resType == "google_spanner_database"
}

func (s spannerDBShortVersionRetention) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "version_retention_period")
	if !present || !known {
		return nil // absent (default 1h is fine) or unresolved
	}
	secs, ok := parseDurationHMS(v)
	if !ok {
		return nil
	}
	if secs < 3600 {
		return []ir.Finding{mkFinding(s, r, "version_retention_period", span,
			v, "version_retention_period >= \"1h\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-249: Spanner database without deletion protection
// ---------------------------------------------------------------------------

type spannerDBNoDeletionProtection struct{}

func (spannerDBNoDeletionProtection) ID() string { return "AEGIS-GCP-249" }
func (spannerDBNoDeletionProtection) Title() string {
	return "Spanner database without deletion protection"
}
func (spannerDBNoDeletionProtection) Description() string {
	return "google_spanner_database with deletion_protection = false can " +
		"be destroyed by an errant apply or compromised credential. " +
		"Enable deletion protection for production databases."
}
func (spannerDBNoDeletionProtection) Severity() ir.Severity { return ir.SeverityMedium }

func (spannerDBNoDeletionProtection) AppliesTo(resType string) bool {
	return resType == "google_spanner_database"
}

func (s spannerDBNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "deletion_protection")
	if !present || !known {
		return nil // only explicit false fires
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "deletion_protection", span,
			"false", "deletion_protection = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-250: Spanner database without drop protection
// ---------------------------------------------------------------------------

type spannerDBNoDropProtection struct{}

func (spannerDBNoDropProtection) ID() string { return "AEGIS-GCP-250" }
func (spannerDBNoDropProtection) Title() string {
	return "Spanner database without drop protection"
}
func (spannerDBNoDropProtection) Description() string {
	return "google_spanner_database with enable_drop_protection = false " +
		"can be dropped through the API by anyone with spanner admin " +
		"rights. Enable drop protection for production databases."
}
func (spannerDBNoDropProtection) Severity() ir.Severity { return ir.SeverityLow }

func (spannerDBNoDropProtection) AppliesTo(resType string) bool {
	return resType == "google_spanner_database"
}

func (s spannerDBNoDropProtection) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "enable_drop_protection")
	if !present || !known {
		return nil // only explicit false fires
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "enable_drop_protection", span,
			"false", "enable_drop_protection = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-251: Spanner instance with force destroy
// ---------------------------------------------------------------------------

type spannerInstanceForceDestroy struct{}

func (spannerInstanceForceDestroy) ID() string { return "AEGIS-GCP-251" }
func (spannerInstanceForceDestroy) Title() string {
	return "Spanner instance with force destroy enabled"
}
func (spannerInstanceForceDestroy) Description() string {
	return "google_spanner_instance with force_destroy = true lets " +
		"Terraform delete the instance even while backups exist, " +
		"removing a safety guardrail. Keep force_destroy = false for " +
		"production instances."
}
func (spannerInstanceForceDestroy) Severity() ir.Severity { return ir.SeverityLow }

func (spannerInstanceForceDestroy) AppliesTo(resType string) bool {
	return resType == "google_spanner_instance"
}

func (s spannerInstanceForceDestroy) Check(r ir.Resource) []ir.Finding {
	fd, span, present, known := getBool(r, "force_destroy")
	if !present || !known {
		return nil
	}
	if fd {
		return []ir.Finding{mkFinding(s, r, "force_destroy", span,
			"true", "force_destroy = false")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-252: Firestore database without CMEK
// ---------------------------------------------------------------------------

type firestoreNoCMEK struct{}

func (firestoreNoCMEK) ID() string { return "AEGIS-GCP-252" }
func (firestoreNoCMEK) Title() string {
	return "Firestore database without customer-managed encryption"
}
func (firestoreNoCMEK) Description() string {
	return "google_firestore_database without cmek_config.kms_key_name " +
		"relies on Google-managed keys. Assign a customer-managed Cloud " +
		"KMS key."
}
func (firestoreNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (firestoreNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_firestore_database"
}

func (s firestoreNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"cmek_config"}, "kms_key_name", "cmek_config")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-253: Firestore database with delete protection disabled
// ---------------------------------------------------------------------------

type firestoreDeleteProtectionDisabled struct{}

func (firestoreDeleteProtectionDisabled) ID() string { return "AEGIS-GCP-253" }
func (firestoreDeleteProtectionDisabled) Title() string {
	return "Firestore database with delete protection disabled"
}
func (firestoreDeleteProtectionDisabled) Description() string {
	return "google_firestore_database with delete_protection_state = " +
		"\"DELETE_PROTECTION_DISABLED\" can be deleted outright. Enable " +
		"delete protection for production databases."
}
func (firestoreDeleteProtectionDisabled) Severity() ir.Severity { return ir.SeverityLow }

func (firestoreDeleteProtectionDisabled) AppliesTo(resType string) bool {
	return resType == "google_firestore_database"
}

func (s firestoreDeleteProtectionDisabled) Check(r ir.Resource) []ir.Finding {
	st, span, present, known := getString(r, "delete_protection_state")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(st), "DELETE_PROTECTION_DISABLED") {
		return []ir.Finding{mkFinding(s, r, "delete_protection_state", span, st,
			"delete_protection_state = \"DELETE_PROTECTION_ENABLED\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-254: Firestore database without point-in-time recovery
// ---------------------------------------------------------------------------

type firestorePITRDisabled struct{}

func (firestorePITRDisabled) ID() string { return "AEGIS-GCP-254" }
func (firestorePITRDisabled) Title() string {
	return "Firestore database without point-in-time recovery"
}
func (firestorePITRDisabled) Description() string {
	return "google_firestore_database with " +
		"point_in_time_recovery_enablement = " +
		"\"POINT_IN_TIME_RECOVERY_DISABLED\" cannot be restored to a " +
		"point in time after data loss or corruption. Enable " +
		"point-in-time recovery."
}
func (firestorePITRDisabled) Severity() ir.Severity { return ir.SeverityMedium }

func (firestorePITRDisabled) AppliesTo(resType string) bool {
	return resType == "google_firestore_database"
}

func (s firestorePITRDisabled) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "point_in_time_recovery_enablement")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(v), "POINT_IN_TIME_RECOVERY_DISABLED") {
		return []ir.Finding{mkFinding(s, r, "point_in_time_recovery_enablement", span,
			v, "point_in_time_recovery_enablement = \"POINT_IN_TIME_RECOVERY_ENABLED\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-255: Bigtable cluster without CMEK
// ---------------------------------------------------------------------------

type bigtableClusterNoCMEK struct{}

func (bigtableClusterNoCMEK) ID() string { return "AEGIS-GCP-255" }
func (bigtableClusterNoCMEK) Title() string {
	return "Bigtable cluster without customer-managed encryption"
}
func (bigtableClusterNoCMEK) Description() string {
	return "google_bigtable_instance with a cluster block lacking " +
		"kms_key_name relies on Google-managed keys for that cluster's " +
		"data. Assign a customer-managed Cloud KMS key per cluster."
}
func (bigtableClusterNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (bigtableClusterNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_bigtable_instance"
}

func (s bigtableClusterNoCMEK) Check(r ir.Resource) []ir.Finding {
	clusters, span, present, known := getBlocks(r, "cluster")
	if !present || !known || len(clusters) == 0 {
		return nil // no cluster blocks: cannot decide
	}
	for _, c := range clusters {
		key, _, kpresent, kknown := blockString(c, "kms_key_name")
		if kpresent && !kknown {
			return nil // unresolved: cannot decide
		}
		if !kpresent || strings.TrimSpace(key) == "" {
			return []ir.Finding{mkFinding(s, r, "cluster",
				evidenceSpan(span, r.Span),
				"cluster without kms_key_name (Google-managed keys)",
				"cluster { kms_key_name = \"<kms-key>\" }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-256: Bigtable instance without deletion protection
// ---------------------------------------------------------------------------

type bigtableNoDeletionProtection struct{}

func (bigtableNoDeletionProtection) ID() string { return "AEGIS-GCP-256" }
func (bigtableNoDeletionProtection) Title() string {
	return "Bigtable instance without deletion protection"
}
func (bigtableNoDeletionProtection) Description() string {
	return "google_bigtable_instance with deletion_protection = false " +
		"can be destroyed by an errant apply or compromised credential. " +
		"Enable deletion protection for production instances."
}
func (bigtableNoDeletionProtection) Severity() ir.Severity { return ir.SeverityLow }

func (bigtableNoDeletionProtection) AppliesTo(resType string) bool {
	return resType == "google_bigtable_instance"
}

func (s bigtableNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "deletion_protection")
	if !present || !known {
		return nil // only explicit false fires
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "deletion_protection", span,
			"false", "deletion_protection = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-257: Artifact Registry remote repository over plain HTTP
// ---------------------------------------------------------------------------

type artifactRemoteHTTPRepository struct{}

func (artifactRemoteHTTPRepository) ID() string { return "AEGIS-GCP-257" }
func (artifactRemoteHTTPRepository) Title() string {
	return "Artifact Registry remote repository over plain HTTP"
}
func (artifactRemoteHTTPRepository) Description() string {
	return "google_artifact_registry_repository with a remote repository " +
		"URI starting with http:// pulls artifacts over unencrypted " +
		"HTTP, exposing them to tampering and credential theft. Use " +
		"https:// upstream URIs."
}
func (artifactRemoteHTTPRepository) Severity() ir.Severity { return ir.SeverityHigh }

func (artifactRemoteHTTPRepository) AppliesTo(resType string) bool {
	return resType == "google_artifact_registry_repository"
}

// remoteRepoFormats lists remote_repository_config sub-blocks that carry a
// custom_repository { uri } leaf.
var remoteRepoFormats = []string{
	"docker_repository", "maven_repository", "npm_repository", "python_repository",
}

func (s artifactRemoteHTTPRepository) Check(r ir.Resource) []ir.Finding {
	remotes, span, present, known := getBlocks(r, "remote_repository_config")
	if !present || !known {
		return nil
	}
	for _, rem := range remotes {
		for _, format := range remoteRepoFormats {
			for _, fr := range blockList(rem, format) {
				for _, cr := range blockList(fr, "custom_repository") {
					uri, uspan, upresent, uknown := blockString(cr, "uri")
					if !upresent || !uknown {
						continue
					}
					if strings.HasPrefix(strings.ToLower(strings.TrimSpace(uri)), "http://") {
						return []ir.Finding{mkFinding(s, r,
							"remote_repository_config."+format+".custom_repository.uri",
							evidenceSpan(uspan, span), uri,
							"uri = \"https://<upstream>\"")}
					}
				}
			}
		}
		// Best-effort: APT/YUM public repositories carry repository_base.
		for _, format := range []string{"apt_repository", "yum_repository"} {
			for _, fr := range blockList(rem, format) {
				for _, pr := range blockList(fr, "public_repository") {
					base, bspan, bpresent, bknown := blockString(pr, "repository_base")
					if !bpresent || !bknown {
						continue
					}
					if strings.HasPrefix(strings.ToLower(strings.TrimSpace(base)), "http://") {
						return []ir.Finding{mkFinding(s, r,
							"remote_repository_config."+format+".public_repository.repository_base",
							evidenceSpan(bspan, span), base,
							"repository_base = \"https://<upstream>\"")}
					}
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-258: Artifact Registry cleanup policies in dry-run mode
// ---------------------------------------------------------------------------

type artifactCleanupPolicyDryRun struct{}

func (artifactCleanupPolicyDryRun) ID() string { return "AEGIS-GCP-258" }
func (artifactCleanupPolicyDryRun) Title() string {
	return "Artifact Registry cleanup policies in dry-run mode"
}
func (artifactCleanupPolicyDryRun) Description() string {
	return "google_artifact_registry_repository with " +
		"cleanup_policy_dry_run = true evaluates cleanup policies without " +
		"enforcing them, so stale and vulnerable artifacts accumulate. " +
		"Set cleanup_policy_dry_run = false to enforce cleanup."
}
func (artifactCleanupPolicyDryRun) Severity() ir.Severity { return ir.SeverityLow }

func (artifactCleanupPolicyDryRun) AppliesTo(resType string) bool {
	return resType == "google_artifact_registry_repository"
}

func (s artifactCleanupPolicyDryRun) Check(r ir.Resource) []ir.Finding {
	dry, span, present, known := getBool(r, "cleanup_policy_dry_run")
	if !present || !known {
		return nil
	}
	if dry {
		return []ir.Finding{mkFinding(s, r, "cleanup_policy_dry_run", span,
			"true", "cleanup_policy_dry_run = false")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-259: Artifact Registry Docker repository with mutable tags
// ---------------------------------------------------------------------------

type artifactMutableDockerTags struct{}

func (artifactMutableDockerTags) ID() string { return "AEGIS-GCP-259" }
func (artifactMutableDockerTags) Title() string {
	return "Artifact Registry Docker repository with mutable tags"
}
func (artifactMutableDockerTags) Description() string {
	return "google_artifact_registry_repository with format = \"DOCKER\" " +
		"and docker_config.immutable_tags not true allows image tags to " +
		"be overwritten, breaking supply-chain integrity. Enable " +
		"immutable tags."
}
func (artifactMutableDockerTags) Severity() ir.Severity { return ir.SeverityMedium }

func (artifactMutableDockerTags) AppliesTo(resType string) bool {
	return resType == "google_artifact_registry_repository"
}

func (s artifactMutableDockerTags) Check(r ir.Resource) []ir.Finding {
	format, _, present, known := getString(r, "format")
	if !present || !known {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(format), "DOCKER") {
		return nil
	}
	blks, span, dpresent, dknown := getBlocks(r, "docker_config")
	if dpresent && !dknown {
		return nil
	}
	if !dpresent || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "docker_config",
			evidenceSpan(span, r.Span),
			"absent (immutable_tags defaults to false)",
			"docker_config { immutable_tags = true }")}
	}
	for _, b := range blks {
		imm, ispan, ipresent, iknown := blockBool(b, "immutable_tags")
		if ipresent && !iknown {
			return nil // unresolved: cannot decide
		}
		if ipresent && iknown && imm {
			return nil
		}
		if ipresent && iknown && !imm {
			return []ir.Finding{mkFinding(s, r, "docker_config.immutable_tags",
				evidenceSpan(ispan, span), "false",
				"docker_config { immutable_tags = true }")}
		}
	}
	return []ir.Finding{mkFinding(s, r, "docker_config",
		evidenceSpan(span, r.Span),
		"docker_config without immutable_tags (defaults to false)",
		"docker_config { immutable_tags = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-260: Artifact Registry repository IAM grants to the public
// ---------------------------------------------------------------------------

type artifactRepoPublicIAM struct{}

func (artifactRepoPublicIAM) ID() string { return "AEGIS-GCP-260" }
func (artifactRepoPublicIAM) Title() string {
	return "Artifact Registry repository IAM grants to the public"
}
func (artifactRepoPublicIAM) Description() string {
	return "google_artifact_registry_repository_iam_binding/member " +
		"granting any role to allUsers or allAuthenticatedUsers exposes " +
		"artifacts publicly. Remove public members."
}
func (artifactRepoPublicIAM) Severity() ir.Severity { return ir.SeverityCritical }

func (artifactRepoPublicIAM) AppliesTo(resType string) bool {
	return resType == "google_artifact_registry_repository_iam_binding" ||
		resType == "google_artifact_registry_repository_iam_member"
}

func (s artifactRepoPublicIAM) Check(r ir.Resource) []ir.Finding {
	switch r.Type {
	case "google_artifact_registry_repository_iam_binding":
		members, span, ok := getStringList(r, "members")
		if !ok {
			return nil // members absent or unresolved: cannot decide
		}
		for _, m := range members {
			if isPublicMember(m) {
				return []ir.Finding{mkFinding(s, r, "members", span,
					m, "remove allUsers/allAuthenticatedUsers from the binding")}
			}
		}
		return nil
	case "google_artifact_registry_repository_iam_member":
		member, span, present, known := getString(r, "member")
		if !present || !known {
			return nil
		}
		if isPublicMember(member) {
			return []ir.Finding{mkFinding(s, r, "member", span,
				member, "remove allUsers/allAuthenticatedUsers from the member")}
		}
		return nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-261: Artifact Registry Maven repository allows snapshot overwrites
// ---------------------------------------------------------------------------

type mavenAllowSnapshotOverwrites struct{}

func (mavenAllowSnapshotOverwrites) ID() string { return "AEGIS-GCP-261" }
func (mavenAllowSnapshotOverwrites) Title() string {
	return "Artifact Registry Maven repository allows snapshot overwrites"
}
func (mavenAllowSnapshotOverwrites) Description() string {
	return "google_artifact_registry_repository with " +
		"maven_config.allow_snapshot_overwrites = true lets mutable " +
		"snapshot versions be replaced, undermining build " +
		"reproducibility. Disable snapshot overwrites."
}
func (mavenAllowSnapshotOverwrites) Severity() ir.Severity { return ir.SeverityMedium }

func (mavenAllowSnapshotOverwrites) AppliesTo(resType string) bool {
	return resType == "google_artifact_registry_repository"
}

func (s mavenAllowSnapshotOverwrites) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "maven_config")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		allow, aspan, apresent, aknown := blockBool(b, "allow_snapshot_overwrites")
		if apresent && !aknown {
			return nil // unresolved: cannot decide
		}
		if apresent && aknown && allow {
			return []ir.Finding{mkFinding(s, r, "maven_config.allow_snapshot_overwrites",
				evidenceSpan(aspan, span), "true",
				"allow_snapshot_overwrites = false")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-262: Artifact Registry Maven repository with snapshot version policy
// ---------------------------------------------------------------------------

type mavenSnapshotVersionPolicy struct{}

func (mavenSnapshotVersionPolicy) ID() string { return "AEGIS-GCP-262" }
func (mavenSnapshotVersionPolicy) Title() string {
	return "Artifact Registry Maven repository with snapshot version policy"
}
func (mavenSnapshotVersionPolicy) Description() string {
	return "google_artifact_registry_repository with " +
		"maven_config.version_policy = \"SNAPSHOT\" accepts mutable " +
		"snapshot versions, weakening supply-chain guarantees. Use " +
		"version_policy = \"RELEASE\" for immutable releases."
}
func (mavenSnapshotVersionPolicy) Severity() ir.Severity { return ir.SeverityLow }

func (mavenSnapshotVersionPolicy) AppliesTo(resType string) bool {
	return resType == "google_artifact_registry_repository"
}

func (s mavenSnapshotVersionPolicy) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "maven_config")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		pol, pspan, ppresent, pknown := blockString(b, "version_policy")
		if ppresent && !pknown {
			return nil // unresolved: cannot decide
		}
		if ppresent && pknown && strings.EqualFold(strings.TrimSpace(pol), "SNAPSHOT") {
			return []ir.Finding{mkFinding(s, r, "maven_config.version_policy",
				evidenceSpan(pspan, span), pol, "version_policy = \"RELEASE\"")}
		}
	}
	return nil
}
