// Package gcp — extended rule pack part 3 (AEGIS-GCP-025..100).
//
// Covers Cloud Storage hardening, BigQuery, Cloud SQL, GKE, Compute,
// Firewall, IAM, KMS, Logging, DNS, Pub/Sub, Cloud Functions/Run gaps.
package gcp

import (
	"strings"

	"aegis/internal/ir"
)

// GCP3Rules returns the extended GCP rules in ID order.
func GCP3Rules() []ir.Rule {
	return []ir.Rule{
		// Storage 025-032
		bucketNoCMEK{}, bucketPublicACL{}, bucketNoLogging{},
		bucketWebsiteEnabled{}, bucketWildcardCORS{}, bucketForceDestroy{},
		bucketNoLifecycle{}, bucketNoPAP{},
		// BigQuery 033-038
		bqPublicAccess{}, bqNoTableExpiration{}, bqTableNoCMEK{},
		bqPrimitiveRole{}, bqNoDeletionProtection{}, bqViewerAllUsers{},
		// Cloud SQL 039-046
		sqlNoPITR{}, sqlOpenAuthorizedNetworks{}, sqlWildcardUserHost{},
		sqlNoMaintWindow{}, sqlOldVersion{}, sqlNoIAMAuth{},
		sqlLocalInfile{}, sqlNoLogDisconnections{},
		// GKE 047-056
		gkeNoWorkloadIdentity{}, gkeNoAutoUpgrade{},
		gkeNoAutoRepair{}, gkeBasicAuth{}, gkeClientCert{},
		gkeDefaultSAFullScope{}, gkeNoIntranodeVisibility{},
		gkeNoShieldedNodes{}, gkeNoConfidentialNodes{},
		// Compute 057-066
		instanceIPForward{}, instanceSerialPort{}, instanceNoSecureBoot{},
		instanceNoOSLogin{}, instanceDiskNoCMEK{}, instanceDefaultSA{},
		instanceNoDeletionProtection{},
		instanceProjectSSHKeys{}, computeDiskNoCMEK{},
		// Firewall 067-071
		firewallOpenRDP{}, firewallAllPorts{}, firewallNoLogging{},
		firewallAllProtocols{}, firewallEgressAll{},
		// IAM 072-080
		iamOwnerBinding{}, iamEditorBinding{}, iamViewerUser{},
		saUserManagedKey{}, iamMemberPublic{}, saIAMBindingPublic{},
		customRoleBroad{}, iamNoAuditConfig{}, workloadPoolNoOIDC{},
		// KMS 081-084
		kmsLongRotation{}, kmsIAMPublic{}, kmsAdminToUser{},
		kmsWeakAlgorithm{},
		// Logging 085-090
		sinkNoUniqueWriter{}, auditExemptAllUsers{}, auditNoDataRead{},
		projectAutoNetwork{}, projectMetadataNoOSLogin{}, logSinkNoFilter{},
		// DNS 091-093
		dnsPolicyNoLogging{}, dnsWildcardRecord{}, dnsWeakDNSSEC{},
		// Pub/Sub 094-096
		pubsubNoRetention{}, pubsubNoDeadLetter{}, pubsubTopicPublic{},
		// Functions/Run 097-100
		cloudRunPublic{}, functionNoMaxInstances{}, cloudRunDefaultSA{},
		functionPublicSource{},
	}
}

// ---------------------------------------------------------------------------
// Storage: AEGIS-GCP-025..032
// ---------------------------------------------------------------------------

// AEGIS-GCP-025: GCS bucket without CMEK
type bucketNoCMEK struct{}

func (bucketNoCMEK) ID() string { return "AEGIS-GCP-025" }
func (bucketNoCMEK) Title() string {
	return "GCS bucket without customer-managed encryption"
}
func (bucketNoCMEK) Description() string {
	return "google_storage_bucket with no encryption block uses Google-managed " +
		"keys. Customer-managed (CMEK) keys are required for regulated data."
}
func (bucketNoCMEK) Severity() ir.Severity { return ir.SeverityHigh }
func (bucketNoCMEK) AppliesTo(t string) bool {
	return t == "google_storage_bucket"
}
func (s bucketNoCMEK) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "encryption")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		if k, _, kp, kk := getString(mapRes(blks[0]), "default_kms_key_name"); kp && kk && k != "" {
			return nil
		}
		// encryption block present but no CMEK key: still Google-managed
		return []ir.Finding{mkFinding(s, r, "encryption", r.Span,
			"no default_kms_key_name", "encryption { default_kms_key_name = ... }")}
	}
	return []ir.Finding{mkFinding(s, r, "encryption", r.Span,
		"absent (Google-managed keys)", "encryption { default_kms_key_name = ... }")}
}

// mapRes adapts a block map for getString-like helpers via a fake resource.
func mapRes(m map[string]ir.Value) ir.Resource {
	return ir.Resource{Attributes: m}
}

// AEGIS-GCP-026: GCS bucket with public ACL
type bucketPublicACL struct{}

func (bucketPublicACL) ID() string { return "AEGIS-GCP-026" }
func (bucketPublicACL) Title() string {
	return "GCS bucket with public canned ACL"
}
func (bucketPublicACL) Description() string {
	return "google_storage_bucket with predefined_acl or acl granting " +
		"publicRead/publicReadWrite exposes objects to the internet."
}
func (bucketPublicACL) Severity() ir.Severity { return ir.SeverityCritical }
func (bucketPublicACL) AppliesTo(t string) bool {
	return t == "google_storage_bucket" || t == "google_storage_bucket_acl"
}
func (s bucketPublicACL) Check(r ir.Resource) []ir.Finding {
	for _, attr := range []string{"predefined_acl", "acl"} {
		v, span, present, known := getString(r, attr)
		if !present || !known {
			continue
		}
		lv := strings.ToLower(v)
		if strings.Contains(lv, "publicread") || strings.Contains(lv, "publicreadwrite") {
			return []ir.Finding{mkFinding(s, r, attr, span,
				v, "private (or omitted)")}
		}
	}
	// role_entity grants to allUsers
	for _, attr := range []string{"role_entity"} {
		lst, span, ok := getStringList(r, attr)
		if !ok {
			continue
		}
		for _, e := range lst {
			if strings.Contains(strings.ToLower(e), "allusers") {
				return []ir.Finding{mkFinding(s, r, attr, span,
					e, "remove allUsers grants")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-027: GCS bucket without access logging
type bucketNoLogging struct{}

func (bucketNoLogging) ID() string { return "AEGIS-GCP-027" }
func (bucketNoLogging) Title() string {
	return "GCS bucket without access logging"
}
func (bucketNoLogging) Description() string {
	return "google_storage_bucket with no logging block has no audit trail " +
		"of object access."
}
func (bucketNoLogging) Severity() ir.Severity { return ir.SeverityMedium }
func (bucketNoLogging) AppliesTo(t string) bool {
	return t == "google_storage_bucket"
}
func (s bucketNoLogging) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBlocks(r, "logging")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "logging", r.Span,
			"absent", "logging { log_bucket = ... log_object_prefix = ... }")}
	}
	return nil
}

// AEGIS-GCP-028: GCS bucket with website hosting enabled
type bucketWebsiteEnabled struct{}

func (bucketWebsiteEnabled) ID() string { return "AEGIS-GCP-028" }
func (bucketWebsiteEnabled) Title() string {
	return "GCS bucket with website hosting enabled"
}
func (bucketWebsiteEnabled) Description() string {
	return "google_storage_bucket with a website block serves content over " +
		"HTTP to the public internet."
}
func (bucketWebsiteEnabled) Severity() ir.Severity { return ir.SeverityHigh }
func (bucketWebsiteEnabled) AppliesTo(t string) bool {
	return t == "google_storage_bucket"
}
func (s bucketWebsiteEnabled) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "website")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return []ir.Finding{mkFinding(s, r, "website", r.Span,
			"website hosting enabled", "remove the website block")}
	}
	return nil
}

// AEGIS-GCP-029: GCS bucket CORS with wildcard origin
type bucketWildcardCORS struct{}

func (bucketWildcardCORS) ID() string { return "AEGIS-GCP-029" }
func (bucketWildcardCORS) Title() string {
	return "GCS bucket CORS allows any origin"
}
func (bucketWildcardCORS) Description() string {
	return "google_storage_bucket cors block with origin \"*\" allows any " +
		"website to read bucket objects via browsers."
}
func (bucketWildcardCORS) Severity() ir.Severity { return ir.SeverityMedium }
func (bucketWildcardCORS) AppliesTo(t string) bool {
	return t == "google_storage_bucket"
}
func (s bucketWildcardCORS) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "cors")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		origins, span, ok := getStringList(mapRes(b), "origin")
		if !ok {
			continue
		}
		for _, o := range origins {
			if strings.TrimSpace(o) == "*" {
				return []ir.Finding{mkFinding(s, r, "cors.origin", span,
					"*", "explicit allowed origins")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-030: GCS bucket with force_destroy
type bucketForceDestroy struct{}

func (bucketForceDestroy) ID() string { return "AEGIS-GCP-030" }
func (bucketForceDestroy) Title() string {
	return "GCS bucket with force_destroy enabled"
}
func (bucketForceDestroy) Description() string {
	return "google_storage_bucket with force_destroy = true allows " +
		"terraform destroy to delete non-empty buckets, risking data loss."
}
func (bucketForceDestroy) Severity() ir.Severity { return ir.SeverityLow }
func (bucketForceDestroy) AppliesTo(t string) bool {
	return t == "google_storage_bucket"
}
func (s bucketForceDestroy) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["force_destroy"]
	if !ok || !v.Known {
		return nil
	}
	if b, ok := v.AsBool(); ok && b {
		return []ir.Finding{mkFinding(s, r, "force_destroy", v.Span,
			"true", "false (or omitted)")}
	}
	return nil
}

// AEGIS-GCP-031: GCS bucket without lifecycle rules
type bucketNoLifecycle struct{}

func (bucketNoLifecycle) ID() string { return "AEGIS-GCP-031" }
func (bucketNoLifecycle) Title() string {
	return "GCS bucket without lifecycle rules"
}
func (bucketNoLifecycle) Description() string {
	return "google_storage_bucket with no lifecycle_rule accumulates " +
		"objects indefinitely; hygiene finding."
}
func (bucketNoLifecycle) Severity() ir.Severity { return ir.SeverityLow }
func (bucketNoLifecycle) AppliesTo(t string) bool {
	return t == "google_storage_bucket"
}
func (s bucketNoLifecycle) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBlocks(r, "lifecycle_rule")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "lifecycle_rule", r.Span,
			"absent", "lifecycle_rule { ... }")}
	}
	return nil
}

// AEGIS-GCP-032: GCS bucket without public access prevention
type bucketNoPAP struct{}

func (bucketNoPAP) ID() string { return "AEGIS-GCP-032" }
func (bucketNoPAP) Title() string {
	return "GCS bucket without public access prevention"
}
func (bucketNoPAP) Description() string {
	return "google_storage_bucket without public_access_prevention = " +
		"\"enforced\" can be made public via ACLs or IAM."
}
func (bucketNoPAP) Severity() ir.Severity { return ir.SeverityMedium }
func (bucketNoPAP) AppliesTo(t string) bool {
	return t == "google_storage_bucket"
}
func (s bucketNoPAP) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "public_access_prevention")
	if !present {
		return []ir.Finding{mkFinding(s, r, "public_access_prevention", r.Span,
			"absent", "public_access_prevention = \"enforced\"")}
	}
	if !known {
		return nil
	}
	if strings.ToLower(v) != "enforced" {
		return []ir.Finding{mkFinding(s, r, "public_access_prevention", span,
			v, "public_access_prevention = \"enforced\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BigQuery: AEGIS-GCP-033..038
// ---------------------------------------------------------------------------

// AEGIS-GCP-033: BigQuery dataset with public access entry
type bqPublicAccess struct{}

func (bqPublicAccess) ID() string { return "AEGIS-GCP-033" }
func (bqPublicAccess) Title() string {
	return "BigQuery dataset with public access"
}
func (bqPublicAccess) Description() string {
	return "google_bigquery_dataset access entry granting access to " +
		"allUsers or allAuthenticatedUsers exposes dataset data publicly."
}
func (bqPublicAccess) Severity() ir.Severity { return ir.SeverityCritical }
func (bqPublicAccess) AppliesTo(t string) bool {
	return t == "google_bigquery_dataset"
}
func (s bqPublicAccess) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "access")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		br := mapRes(b)
		for _, attr := range []string{"special_group", "user_by_email", "group_by_email", "domain"} {
			v, span, p, k := getString(br, attr)
			if !p || !k {
				continue
			}
			lv := strings.ToLower(strings.TrimSpace(v))
			if lv == "allusers" || lv == "allauthenticatedusers" {
				return []ir.Finding{mkFinding(s, r, "access."+attr, span,
					v, "remove public access entries")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-034: BigQuery dataset without default table expiration
type bqNoTableExpiration struct{}

func (bqNoTableExpiration) ID() string { return "AEGIS-GCP-034" }
func (bqNoTableExpiration) Title() string {
	return "BigQuery dataset without default table expiration"
}
func (bqNoTableExpiration) Description() string {
	return "google_bigquery_dataset with no default_table_expiration_ms " +
		"lets tables accumulate data indefinitely; hygiene finding."
}
func (bqNoTableExpiration) Severity() ir.Severity { return ir.SeverityLow }
func (bqNoTableExpiration) AppliesTo(t string) bool {
	return t == "google_bigquery_dataset"
}
func (s bqNoTableExpiration) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "default_table_expiration_ms")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "default_table_expiration_ms", r.Span,
			"absent", "default_table_expiration_ms = 31536000000")}
	}
	return nil
}

// AEGIS-GCP-035: BigQuery table without CMEK
type bqTableNoCMEK struct{}

func (bqTableNoCMEK) ID() string { return "AEGIS-GCP-035" }
func (bqTableNoCMEK) Title() string {
	return "BigQuery table without customer-managed encryption"
}
func (bqTableNoCMEK) Description() string {
	return "google_bigquery_table with no encryption_configuration uses " +
		"Google-managed keys instead of CMEK."
}
func (bqTableNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }
func (bqTableNoCMEK) AppliesTo(t string) bool {
	return t == "google_bigquery_table"
}
func (s bqTableNoCMEK) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "encryption_configuration")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "encryption_configuration", r.Span,
			"absent (Google-managed keys)", "encryption_configuration { kms_key_name = ... }")}
	}
	return nil
}

// AEGIS-GCP-036: BigQuery dataset access with primitive role
type bqPrimitiveRole struct{}

func (bqPrimitiveRole) ID() string { return "AEGIS-GCP-036" }
func (bqPrimitiveRole) Title() string {
	return "BigQuery dataset access with primitive role"
}
func (bqPrimitiveRole) Description() string {
	return "google_bigquery_dataset access entry using roles/owner, " +
		"roles/editor, or roles/viewer grants excessive privileges."
}
func (bqPrimitiveRole) Severity() ir.Severity { return ir.SeverityHigh }
func (bqPrimitiveRole) AppliesTo(t string) bool {
	return t == "google_bigquery_dataset"
}
func (s bqPrimitiveRole) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "access")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		role, span, p, k := getString(mapRes(b), "role")
		if !p || !k {
			continue
		}
		lr := strings.ToLower(strings.TrimSpace(role))
		if lr == "roles/owner" || lr == "roles/editor" {
			return []ir.Finding{mkFinding(s, r, "access.role", span,
				role, "use granular bigquery.* roles")}
		}
	}
	return nil
}

// AEGIS-GCP-037: BigQuery dataset without deletion protection
type bqNoDeletionProtection struct{}

func (bqNoDeletionProtection) ID() string { return "AEGIS-GCP-037" }
func (bqNoDeletionProtection) Title() string {
	return "BigQuery dataset without deletion protection"
}
func (bqNoDeletionProtection) Description() string {
	return "google_bigquery_dataset with deletion_protection = false " +
		"allows terraform destroy to delete the dataset and its data."
}
func (bqNoDeletionProtection) Severity() ir.Severity { return ir.SeverityMedium }
func (bqNoDeletionProtection) AppliesTo(t string) bool {
	return t == "google_bigquery_dataset"
}
func (s bqNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["deletion_protection"]
	if !ok || !v.Known {
		return nil
	}
	if b, ok := v.AsBool(); ok && !b {
		return []ir.Finding{mkFinding(s, r, "deletion_protection", v.Span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-038: BigQuery dataset IAM granting dataViewer to allUsers
type bqViewerAllUsers struct{}

func (bqViewerAllUsers) ID() string { return "AEGIS-GCP-038" }
func (bqViewerAllUsers) Title() string {
	return "BigQuery IAM grants data access to the public"
}
func (bqViewerAllUsers) Description() string {
	return "google_bigquery_dataset_iam_binding/member granting " +
		"roles/bigquery.dataViewer (or admin) to allUsers/allAuthenticatedUsers."
}
func (bqViewerAllUsers) Severity() ir.Severity { return ir.SeverityCritical }
func (bqViewerAllUsers) AppliesTo(t string) bool {
	return t == "google_bigquery_dataset_iam_binding" ||
		t == "google_bigquery_dataset_iam_member"
}
func (s bqViewerAllUsers) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil
	}
	lr := strings.ToLower(role)
	if !strings.Contains(lr, "dataviewer") && !strings.Contains(lr, "dataeditor") && !strings.Contains(lr, "admin") {
		return nil
	}
	checkMember := func(m, attr string, span ir.Span) []ir.Finding {
		lm := strings.ToLower(strings.TrimSpace(m))
		if lm == "allusers" || lm == "allauthenticatedusers" {
			return []ir.Finding{mkFinding(s, r, attr, span, m, "remove public members")}
		}
		return nil
	}
	if r.Type == "google_bigquery_dataset_iam_binding" {
		members, span, ok := getStringList(r, "members")
		if !ok {
			return nil
		}
		for _, m := range members {
			if f := checkMember(m, "members", span); f != nil {
				return f
			}
		}
		return nil
	}
	member, span, p, k := getString(r, "member")
	if !p || !k {
		return nil
	}
	return checkMember(member, "member", span)
}

// ---------------------------------------------------------------------------
// Cloud SQL: AEGIS-GCP-039..046
// ---------------------------------------------------------------------------

// AEGIS-GCP-039: Cloud SQL without point-in-time recovery
type sqlNoPITR struct{}

func (sqlNoPITR) ID() string { return "AEGIS-GCP-039" }
func (sqlNoPITR) Title() string {
	return "Cloud SQL instance without point-in-time recovery"
}
func (sqlNoPITR) Description() string {
	return "google_sql_database_instance with backup_configuration but " +
		"point_in_time_recovery_enabled not true cannot restore to an " +
		"arbitrary timestamp."
}
func (sqlNoPITR) Severity() ir.Severity { return ir.SeverityMedium }
func (sqlNoPITR) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoPITR) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "backup_configuration")
	if !present || !known || len(blks) == 0 {
		return nil // 003 covers missing backups
	}
	en, span, p, k := blockBool(blks[0], "point_in_time_recovery_enabled")
	if !p {
		return []ir.Finding{mkFinding(s, r, "backup_configuration.point_in_time_recovery_enabled",
			r.Span, "absent", "point_in_time_recovery_enabled = true")}
	}
	if !k {
		return nil
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "backup_configuration.point_in_time_recovery_enabled",
			span, "false", "true")}
	}
	return nil
}

// AEGIS-GCP-040: Cloud SQL with open authorized networks
type sqlOpenAuthorizedNetworks struct{}

func (sqlOpenAuthorizedNetworks) ID() string { return "AEGIS-GCP-040" }
func (sqlOpenAuthorizedNetworks) Title() string {
	return "Cloud SQL instance allows connections from the internet"
}
func (sqlOpenAuthorizedNetworks) Description() string {
	return "google_sql_database_instance ip_configuration authorized_networks " +
		"with 0.0.0.0/0 exposes the database to the internet."
}
func (sqlOpenAuthorizedNetworks) Severity() ir.Severity { return ir.SeverityCritical }
func (sqlOpenAuthorizedNetworks) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlOpenAuthorizedNetworks) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		ipc := blockList(st, "ip_configuration")
		for _, ip := range ipc {
			nets := blockList(ip, "authorized_networks")
			for _, n := range nets {
				v, span, p, k := getString(mapRes(n), "value")
				if !p || !k {
					continue
				}
				if strings.TrimSpace(v) == "0.0.0.0/0" {
					return []ir.Finding{mkFinding(s, r, "authorized_networks.value", span,
						"0.0.0.0/0", "restricted CIDR ranges")}
				}
			}
		}
	}
	return nil
}

// AEGIS-GCP-041: Cloud SQL user with wildcard host
type sqlWildcardUserHost struct{}

func (sqlWildcardUserHost) ID() string { return "AEGIS-GCP-041" }
func (sqlWildcardUserHost) Title() string {
	return "Cloud SQL user allows connections from any host"
}
func (sqlWildcardUserHost) Description() string {
	return "google_sql_user with host = \"%\" allows the database user to " +
		"connect from any host."
}
func (sqlWildcardUserHost) Severity() ir.Severity { return ir.SeverityHigh }
func (sqlWildcardUserHost) AppliesTo(t string) bool {
	return t == "google_sql_user"
}
func (s sqlWildcardUserHost) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "host")
	if !present || !known {
		return nil
	}
	if strings.TrimSpace(v) == "%" {
		return []ir.Finding{mkFinding(s, r, "host", span,
			"%", "specific host or IP")}
	}
	return nil
}

// AEGIS-GCP-042: Cloud SQL without maintenance window
type sqlNoMaintWindow struct{}

func (sqlNoMaintWindow) ID() string { return "AEGIS-GCP-042" }
func (sqlNoMaintWindow) Title() string {
	return "Cloud SQL instance without maintenance window"
}
func (sqlNoMaintWindow) Description() string {
	return "google_sql_database_instance with no maintenance_window lets " +
		"GCP apply disruptive maintenance at any time; hygiene finding."
}
func (sqlNoMaintWindow) Severity() ir.Severity { return ir.SeverityLow }
func (sqlNoMaintWindow) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoMaintWindow) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		mw := blockList(st, "maintenance_window")
		if len(mw) > 0 {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "settings.maintenance_window", r.Span,
		"absent", "maintenance_window { day = 7 hour = 3 }")}
}

// AEGIS-GCP-043: Cloud SQL on old database version
type sqlOldVersion struct{}

func (sqlOldVersion) ID() string { return "AEGIS-GCP-043" }
func (sqlOldVersion) Title() string {
	return "Cloud SQL instance on outdated database version"
}
func (sqlOldVersion) Description() string {
	return "google_sql_database_instance on MYSQL_5_7, POSTGRES_11 or older " +
		"misses security patches."
}
func (sqlOldVersion) Severity() ir.Severity { return ir.SeverityMedium }
func (sqlOldVersion) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlOldVersion) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "database_version")
	if !present || !known {
		return nil
	}
	old := []string{"MYSQL_5_6", "MYSQL_5_7", "POSTGRES_9_6", "POSTGRES_10",
		"POSTGRES_11", "SQLSERVER_2017_STANDARD", "SQLSERVER_2017_ENTERPRISE"}
	uv := strings.ToUpper(strings.TrimSpace(v))
	for _, o := range old {
		if uv == o {
			return []ir.Finding{mkFinding(s, r, "database_version", span,
				v, "a supported database version")}
		}
	}
	return nil
}

// AEGIS-GCP-044: Cloud SQL without IAM database authentication
type sqlNoIAMAuth struct{}

func (sqlNoIAMAuth) ID() string { return "AEGIS-GCP-044" }
func (sqlNoIAMAuth) Title() string {
	return "Cloud SQL instance without IAM database authentication"
}
func (sqlNoIAMAuth) Description() string {
	return "google_sql_database_instance without database flag " +
		"cloudsql.iam_authentication=on forces password-only auth."
}
func (sqlNoIAMAuth) Severity() ir.Severity { return ir.SeverityMedium }
func (sqlNoIAMAuth) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoIAMAuth) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		flags := blockList(st, "database_flags")
		for _, f := range flags {
			name, _, np, nk := getString(mapRes(f), "name")
			if !np || !nk {
				continue
			}
			if strings.ToLower(name) == "cloudsql.iam_authentication" {
				val, _, vp, vk := getString(mapRes(f), "value")
				if vp && vk && strings.ToLower(val) == "on" {
					return nil
				}
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "settings.database_flags", r.Span,
		"cloudsql.iam_authentication not enabled",
		"database_flags { name = \"cloudsql.iam_authentication\" value = \"on\" }")}
}

// AEGIS-GCP-045: Cloud SQL with local_infile enabled
type sqlLocalInfile struct{}

func (sqlLocalInfile) ID() string { return "AEGIS-GCP-045" }
func (sqlLocalInfile) Description() string {
	return "google_sql_database_instance with database flag local_infile=on " +
		"allows LOAD DATA LOCAL, a classic exfiltration primitive."
}
func (sqlLocalInfile) Title() string {
	return "Cloud SQL instance with local_infile enabled"
}
func (sqlLocalInfile) Severity() ir.Severity { return ir.SeverityMedium }
func (sqlLocalInfile) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlLocalInfile) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		for _, f := range blockList(st, "database_flags") {
			name, _, np, nk := getString(mapRes(f), "name")
			if !np || !nk || strings.ToLower(name) != "local_infile" {
				continue
			}
			val, span, vp, vk := getString(mapRes(f), "value")
			if vp && vk && (val == "on" || val == "1") {
				return []ir.Finding{mkFinding(s, r, "database_flags.local_infile", span,
					val, "off")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-046: Cloud SQL without log_disconnections
type sqlNoLogDisconnections struct{}

func (sqlNoLogDisconnections) ID() string { return "AEGIS-GCP-046" }
func (sqlNoLogDisconnections) Title() string {
	return "Cloud SQL instance without log_disconnections"
}
func (sqlNoLogDisconnections) Description() string {
	return "google_sql_database_instance without database flag " +
		"log_disconnections=on misses session audit data; hygiene finding."
}
func (sqlNoLogDisconnections) Severity() ir.Severity { return ir.SeverityLow }
func (sqlNoLogDisconnections) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoLogDisconnections) Check(r ir.Resource) []ir.Finding {
	if !sqlIsPostgres(r) {
		return nil
	}
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		for _, f := range blockList(st, "database_flags") {
			name, _, np, nk := getString(mapRes(f), "name")
			if !np || !nk {
				continue
			}
			if strings.ToLower(name) == "log_disconnections" {
				val, _, vp, vk := getString(mapRes(f), "value")
				if vp && vk && (val == "on" || val == "1") {
					return nil
				}
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "settings.database_flags", r.Span,
		"log_disconnections not enabled",
		"database_flags { name = \"log_disconnections\" value = \"on\" }")}
}

// ---------------------------------------------------------------------------
// GKE: AEGIS-GCP-047..056
// ---------------------------------------------------------------------------

// AEGIS-GCP-047: GKE without workload identity
type gkeNoWorkloadIdentity struct{}

func (gkeNoWorkloadIdentity) ID() string { return "AEGIS-GCP-047" }
func (gkeNoWorkloadIdentity) Title() string {
	return "GKE cluster without workload identity"
}
func (gkeNoWorkloadIdentity) Description() string {
	return "google_container_cluster with no workload_identity_config forces " +
		"pods to use node service account credentials."
}
func (gkeNoWorkloadIdentity) Severity() ir.Severity { return ir.SeverityHigh }
func (gkeNoWorkloadIdentity) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeNoWorkloadIdentity) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "workload_identity_config")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "workload_identity_config", r.Span,
			"absent", "workload_identity_config { workload_pool = \"...svc.id.goog\" }")}
	}
	return nil
}

// AEGIS-GCP-048: GKE without binary authorization

// AEGIS-GCP-049: GKE node auto-upgrade disabled
type gkeNoAutoUpgrade struct{}

func (gkeNoAutoUpgrade) ID() string { return "AEGIS-GCP-049" }
func (gkeNoAutoUpgrade) Title() string {
	return "GKE node pool with auto-upgrade disabled"
}
func (gkeNoAutoUpgrade) Description() string {
	return "google_container_node_pool with management auto_upgrade = false " +
		"misses security patches to nodes."
}
func (gkeNoAutoUpgrade) Severity() ir.Severity { return ir.SeverityMedium }
func (gkeNoAutoUpgrade) AppliesTo(t string) bool {
	return t == "google_container_node_pool" || t == "google_container_cluster"
}
func (s gkeNoAutoUpgrade) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "management")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		en, span, p, k := blockBool(b, "auto_upgrade")
		if !p || !k {
			continue
		}
		if !en {
			return []ir.Finding{mkFinding(s, r, "management.auto_upgrade", span,
				"false", "true")}
		}
	}
	return nil
}

// AEGIS-GCP-050: GKE node auto-repair disabled
type gkeNoAutoRepair struct{}

func (gkeNoAutoRepair) ID() string { return "AEGIS-GCP-050" }
func (gkeNoAutoRepair) Title() string {
	return "GKE node pool with auto-repair disabled"
}
func (gkeNoAutoRepair) Description() string {
	return "google_container_node_pool with management auto_repair = false " +
		"leaves unhealthy nodes running."
}
func (gkeNoAutoRepair) Severity() ir.Severity { return ir.SeverityMedium }
func (gkeNoAutoRepair) AppliesTo(t string) bool {
	return t == "google_container_node_pool" || t == "google_container_cluster"
}
func (s gkeNoAutoRepair) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "management")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		en, span, p, k := blockBool(b, "auto_repair")
		if !p || !k {
			continue
		}
		if !en {
			return []ir.Finding{mkFinding(s, r, "management.auto_repair", span,
				"false", "true")}
		}
	}
	return nil
}

// AEGIS-GCP-051: GKE with basic auth enabled
type gkeBasicAuth struct{}

func (gkeBasicAuth) ID() string { return "AEGIS-GCP-051" }
func (gkeBasicAuth) Title() string {
	return "GKE cluster with basic authentication enabled"
}
func (gkeBasicAuth) Description() string {
	return "google_container_cluster master_auth with username/password " +
		"enables weak static credentials for the Kubernetes API."
}
func (gkeBasicAuth) Severity() ir.Severity { return ir.SeverityCritical }
func (gkeBasicAuth) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeBasicAuth) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "master_auth")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		u, span, p, k := getString(mapRes(b), "username")
		if p && k && strings.TrimSpace(u) != "" {
			return []ir.Finding{mkFinding(s, r, "master_auth.username", span,
				"basic auth enabled", "remove username/password; use IAM auth")}
		}
	}
	return nil
}

// AEGIS-GCP-052: GKE with client certificate auth
type gkeClientCert struct{}

func (gkeClientCert) ID() string { return "AEGIS-GCP-052" }
func (gkeClientCert) Title() string {
	return "GKE cluster issuing client certificates"
}
func (gkeClientCert) Description() string {
	return "google_container_cluster master_auth with " +
		"client_certificate_config issue_client_certificate = true creates " +
		"long-lived credentials."
}
func (gkeClientCert) Severity() ir.Severity { return ir.SeverityHigh }
func (gkeClientCert) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeClientCert) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "master_auth")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		cc := blockList(b, "client_certificate_config")
		for _, c := range cc {
			en, span, p, k := blockBool(c, "issue_client_certificate")
			if p && k && en {
				return []ir.Finding{mkFinding(s, r,
					"master_auth.client_certificate_config.issue_client_certificate",
					span, "true", "false")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-053: GKE node pool with default SA and full scopes
type gkeDefaultSAFullScope struct{}

func (gkeDefaultSAFullScope) ID() string { return "AEGIS-GCP-053" }
func (gkeDefaultSAFullScope) Title() string {
	return "GKE node pool with default service account and broad scopes"
}
func (gkeDefaultSAFullScope) Description() string {
	return "google_container_node_pool node_config with the default Compute " +
		"Engine service account and cloud-platform scope gives nodes broad " +
		"GCP API access."
}
func (gkeDefaultSAFullScope) Severity() ir.Severity { return ir.SeverityHigh }
func (gkeDefaultSAFullScope) AppliesTo(t string) bool {
	return t == "google_container_node_pool"
}
func (s gkeDefaultSAFullScope) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "node_config")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		sa, _, sap, sak := getString(mapRes(b), "service_account")
		scopes, _, scp := getStringList(mapRes(b), "oauth_scopes")
		broad := false
		if scp {
			for _, sc := range scopes {
				if strings.Contains(sc, "cloud-platform") {
					broad = true
				}
			}
		}
		isDefault := !sap || !sak || strings.TrimSpace(sa) == "" || strings.Contains(sa, "default")
		if isDefault && broad {
			return []ir.Finding{mkFinding(s, r, "node_config.oauth_scopes", r.Span,
				"default SA with cloud-platform scope",
				"dedicated SA with minimal scopes")}
		}
	}
	return nil
}

// AEGIS-GCP-054: GKE without intranode visibility
type gkeNoIntranodeVisibility struct{}

func (gkeNoIntranodeVisibility) ID() string { return "AEGIS-GCP-054" }
func (gkeNoIntranodeVisibility) Title() string {
	return "GKE cluster without intranode visibility"
}
func (gkeNoIntranodeVisibility) Description() string {
	return "google_container_cluster with enable_intranode_visibility not " +
		"true hides pod-to-pod traffic from flow logs; hygiene finding."
}
func (gkeNoIntranodeVisibility) Severity() ir.Severity { return ir.SeverityLow }
func (gkeNoIntranodeVisibility) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeNoIntranodeVisibility) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["enable_intranode_visibility"]
	if !ok || !v.Known {
		return nil
	}
	if b, ok := v.AsBool(); ok && !b {
		return []ir.Finding{mkFinding(s, r, "enable_intranode_visibility", v.Span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-055: GKE without shielded nodes
type gkeNoShieldedNodes struct{}

func (gkeNoShieldedNodes) ID() string { return "AEGIS-GCP-055" }
func (gkeNoShieldedNodes) Title() string {
	return "GKE cluster without shielded nodes"
}
func (gkeNoShieldedNodes) Description() string {
	return "google_container_cluster with no shielded_nodes block misses " +
		"secure boot and integrity monitoring on nodes."
}
func (gkeNoShieldedNodes) Severity() ir.Severity { return ir.SeverityMedium }
func (gkeNoShieldedNodes) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeNoShieldedNodes) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "shielded_nodes")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "shielded_nodes", r.Span,
			"absent", "shielded_nodes { enabled = true }")}
	}
	en, span, p, k := blockBool(blks[0], "enabled")
	if p && k && !en {
		return []ir.Finding{mkFinding(s, r, "shielded_nodes.enabled", span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-056: GKE without confidential nodes
type gkeNoConfidentialNodes struct{}

func (gkeNoConfidentialNodes) ID() string { return "AEGIS-GCP-056" }
func (gkeNoConfidentialNodes) Title() string {
	return "GKE cluster without confidential nodes"
}
func (gkeNoConfidentialNodes) Description() string {
	return "google_container_cluster node_config without " +
		"confidential_nodes enabled leaves workload memory unencrypted; " +
		"hygiene finding for sensitive workloads."
}
func (gkeNoConfidentialNodes) Severity() ir.Severity { return ir.SeverityLow }
func (gkeNoConfidentialNodes) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeNoConfidentialNodes) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "node_config")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		cn := blockList(b, "confidential_nodes")
		if len(cn) == 0 {
			return []ir.Finding{mkFinding(s, r, "node_config.confidential_nodes", r.Span,
				"absent", "confidential_nodes { enabled = true }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Compute: AEGIS-GCP-057..066
// ---------------------------------------------------------------------------

// AEGIS-GCP-057: Compute instance with IP forwarding
type instanceIPForward struct{}

func (instanceIPForward) ID() string { return "AEGIS-GCP-057" }
func (instanceIPForward) Title() string {
	return "Compute instance with IP forwarding enabled"
}
func (instanceIPForward) Description() string {
	return "google_compute_instance with can_ip_forward = true can route " +
		"traffic for other hosts, enabling MITM positioning."
}
func (instanceIPForward) Severity() ir.Severity { return ir.SeverityMedium }
func (instanceIPForward) AppliesTo(t string) bool {
	return t == "google_compute_instance"
}
func (s instanceIPForward) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["can_ip_forward"]
	if !ok || !v.Known {
		return nil
	}
	if b, ok := v.AsBool(); ok && b {
		return []ir.Finding{mkFinding(s, r, "can_ip_forward", v.Span,
			"true", "false (or omitted)")}
	}
	return nil
}

// AEGIS-GCP-058: Compute instance with serial port enabled
type instanceSerialPort struct{}

func (instanceSerialPort) ID() string { return "AEGIS-GCP-058" }
func (instanceSerialPort) Title() string {
	return "Compute instance with serial port access enabled"
}
func (instanceSerialPort) Description() string {
	return "google_compute_instance metadata serial-port-enable = true " +
		"exposes an interactive serial console."
}
func (instanceSerialPort) Severity() ir.Severity { return ir.SeverityMedium }
func (instanceSerialPort) AppliesTo(t string) bool {
	return t == "google_compute_instance"
}
func (s instanceSerialPort) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "metadata")
	if present && !known {
		return nil
	}
	check := func(m map[string]ir.Value) []ir.Finding {
		v, ok := m["serial-port-enable"]
		if !ok || !v.Known {
			return nil
		}
		if sv, ok := v.AsString(); ok && strings.ToLower(sv) == "true" {
			return []ir.Finding{mkFinding(s, r, "metadata.serial-port-enable", v.Span,
				"true", "false (or omitted)")}
		}
		if bv, ok := v.AsBool(); ok && bv {
			return []ir.Finding{mkFinding(s, r, "metadata.serial-port-enable", v.Span,
				"true", "false (or omitted)")}
		}
		return nil
	}
	if !present {
		if v, ok := r.Attributes["metadata"]; ok && v.Known {
			if m, ok := v.AsMap(); ok {
				return check(m)
			}
		}
		return nil
	}
	for _, b := range blks {
		if f := check(b); f != nil {
			return f
		}
	}
	return nil
}

// AEGIS-GCP-059: Compute instance without secure boot
type instanceNoSecureBoot struct{}

func (instanceNoSecureBoot) ID() string { return "AEGIS-GCP-059" }
func (instanceNoSecureBoot) Title() string {
	return "Compute instance without secure boot"
}
func (instanceNoSecureBoot) Description() string {
	return "google_compute_instance shielded_instance_config without " +
		"enable_secure_boot = true misses boot integrity verification."
}
func (instanceNoSecureBoot) Severity() ir.Severity { return ir.SeverityMedium }
func (instanceNoSecureBoot) AppliesTo(t string) bool {
	return t == "google_compute_instance"
}
func (s instanceNoSecureBoot) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "shielded_instance_config")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "shielded_instance_config", r.Span,
			"absent", "shielded_instance_config { enable_secure_boot = true }")}
	}
	en, span, p, k := blockBool(blks[0], "enable_secure_boot")
	if p && k && !en {
		return []ir.Finding{mkFinding(s, r, "shielded_instance_config.enable_secure_boot",
			span, "false", "true")}
	}
	return nil
}

// AEGIS-GCP-060: Compute instance without OS Login
type instanceNoOSLogin struct{}

func (instanceNoOSLogin) ID() string { return "AEGIS-GCP-060" }
func (instanceNoOSLogin) Title() string {
	return "Compute instance without OS Login"
}
func (instanceNoOSLogin) Description() string {
	return "google_compute_instance metadata without enable-oslogin = TRUE " +
		"falls back to project-wide SSH keys instead of IAM-managed access."
}
func (instanceNoOSLogin) Severity() ir.Severity { return ir.SeverityMedium }
func (instanceNoOSLogin) AppliesTo(t string) bool {
	return t == "google_compute_instance"
}
func (s instanceNoOSLogin) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["metadata"]
	if !ok || !v.Known {
		return nil
	}
	m, ok := v.AsMap()
	if !ok {
		return nil
	}
	ov, ok := m["enable-oslogin"]
	if !ok || !ov.Known {
		return nil // absent: project default may apply; cannot decide
	}
	if sv, ok := ov.AsString(); ok && strings.ToUpper(sv) != "TRUE" {
		return []ir.Finding{mkFinding(s, r, "metadata.enable-oslogin", ov.Span,
			sv, "TRUE")}
	}
	return nil
}

// AEGIS-GCP-061: Compute instance boot disk without CMEK
type instanceDiskNoCMEK struct{}

func (instanceDiskNoCMEK) ID() string { return "AEGIS-GCP-061" }
func (instanceDiskNoCMEK) Title() string {
	return "Compute instance boot disk without customer-managed encryption"
}
func (instanceDiskNoCMEK) Description() string {
	return "google_compute_instance boot_disk initialize_params without " +
		"kms_key_self_link uses Google-managed disk encryption."
}
func (instanceDiskNoCMEK) Severity() ir.Severity { return ir.SeverityHigh }
func (instanceDiskNoCMEK) AppliesTo(t string) bool {
	return t == "google_compute_instance"
}
func (s instanceDiskNoCMEK) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "boot_disk")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		ip := blockList(b, "initialize_params")
		if len(ip) == 0 {
			return []ir.Finding{mkFinding(s, r, "boot_disk.initialize_params", r.Span,
				"absent", "initialize_params { kms_key_self_link = ... }")}
		}
		for _, p := range ip {
			_, _, kp, kk := getString(mapRes(p), "kms_key_self_link")
			if !kp || !kk {
				return []ir.Finding{mkFinding(s, r, "boot_disk.initialize_params.kms_key_self_link",
					r.Span, "absent", "kms_key_self_link = ...")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-062: Compute instance with default service account
type instanceDefaultSA struct{}

func (instanceDefaultSA) ID() string { return "AEGIS-GCP-062" }
func (instanceDefaultSA) Title() string {
	return "Compute instance with default service account"
}
func (instanceDefaultSA) Description() string {
	return "google_compute_instance service_account without an explicit " +
		"email uses the default Compute Engine service account."
}
func (instanceDefaultSA) Severity() ir.Severity { return ir.SeverityMedium }
func (instanceDefaultSA) AppliesTo(t string) bool {
	return t == "google_compute_instance"
}
func (s instanceDefaultSA) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "service_account")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		email, _, p, k := getString(mapRes(b), "email")
		if !p || !k || strings.TrimSpace(email) == "" || strings.Contains(email, "default") {
			return []ir.Finding{mkFinding(s, r, "service_account.email", r.Span,
				"default service account", "dedicated least-privilege service account")}
		}
	}
	return nil
}

// AEGIS-GCP-064: Compute instance without deletion protection
type instanceNoDeletionProtection struct{}

func (instanceNoDeletionProtection) ID() string { return "AEGIS-GCP-064" }
func (instanceNoDeletionProtection) Title() string {
	return "Compute instance without deletion protection"
}
func (instanceNoDeletionProtection) Description() string {
	return "google_compute_instance with deletion_protection = false can " +
		"be deleted accidentally; hygiene finding."
}
func (instanceNoDeletionProtection) Severity() ir.Severity { return ir.SeverityLow }
func (instanceNoDeletionProtection) AppliesTo(t string) bool {
	return t == "google_compute_instance"
}
func (s instanceNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["deletion_protection"]
	if !ok || !v.Known {
		return nil
	}
	if b, ok := v.AsBool(); ok && !b {
		return []ir.Finding{mkFinding(s, r, "deletion_protection", v.Span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-065: Compute instance allowing project SSH keys
type instanceProjectSSHKeys struct{}

func (instanceProjectSSHKeys) ID() string { return "AEGIS-GCP-065" }
func (instanceProjectSSHKeys) Title() string {
	return "Compute instance allows project-wide SSH keys"
}
func (instanceProjectSSHKeys) Description() string {
	return "google_compute_instance metadata without " +
		"block-project-ssh-keys = TRUE accepts project-wide SSH keys."
}
func (instanceProjectSSHKeys) Severity() ir.Severity { return ir.SeverityLow }
func (instanceProjectSSHKeys) AppliesTo(t string) bool {
	return t == "google_compute_instance"
}
func (s instanceProjectSSHKeys) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["metadata"]
	if !ok || !v.Known {
		// No metadata block: project-wide SSH keys are enabled by
		// default, so the instance accepts them.
		return []ir.Finding{mkFinding(s, r, "metadata.block-project-ssh-keys",
			r.Span, "absent (project defaults apply)",
			"block-project-ssh-keys = \"TRUE\"")}
	}
	m, ok := v.AsMap()
	if !ok {
		return nil
	}
	bv, ok := m["block-project-ssh-keys"]
	if !ok {
		// Key absent: defaults to false, so project-wide SSH keys
		// are accepted.
		return []ir.Finding{mkFinding(s, r, "metadata.block-project-ssh-keys",
			v.Span, "absent", "block-project-ssh-keys = \"TRUE\"")}
	}
	if !bv.Known {
		return nil // unresolved: cannot decide
	}
	if sv, ok := bv.AsString(); ok && strings.ToUpper(sv) != "TRUE" {
		return []ir.Finding{mkFinding(s, r, "metadata.block-project-ssh-keys", bv.Span,
			sv, "TRUE")}
	}
	return nil
}

// AEGIS-GCP-066: Compute disk without CMEK
type computeDiskNoCMEK struct{}

func (computeDiskNoCMEK) ID() string { return "AEGIS-GCP-066" }
func (computeDiskNoCMEK) Title() string {
	return "Compute persistent disk without customer-managed encryption"
}
func (computeDiskNoCMEK) Description() string {
	return "google_compute_disk with no disk_encryption_key block uses " +
		"Google-managed encryption instead of CMEK."
}
func (computeDiskNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }
func (computeDiskNoCMEK) AppliesTo(t string) bool {
	return t == "google_compute_disk"
}
func (s computeDiskNoCMEK) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "disk_encryption_key")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "disk_encryption_key", r.Span,
			"absent (Google-managed keys)",
			"disk_encryption_key { kms_key_self_link = ... }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Firewall: AEGIS-GCP-067..071
// ---------------------------------------------------------------------------

// firewallAllows reports whether a firewall rule's allow blocks cover the
// given ports/protocols from the given sources.
func firewallTargetsWorld(r ir.Resource) (sources []string, span ir.Span, ok bool) {
	srcs, s, ok := getStringList(r, "source_ranges")
	if !ok {
		return nil, ir.Span{}, false
	}
	for _, c := range srcs {
		if strings.TrimSpace(c) == "0.0.0.0/0" {
			return srcs, s, true
		}
	}
	return nil, ir.Span{}, false
}

// AEGIS-GCP-067: Firewall allows RDP from the internet
type firewallOpenRDP struct{}

func (firewallOpenRDP) ID() string { return "AEGIS-GCP-067" }
func (firewallOpenRDP) Title() string {
	return "Firewall allows RDP from the internet"
}
func (firewallOpenRDP) Description() string {
	return "google_compute_firewall with an allow block for TCP 3389 from " +
		"0.0.0.0/0 exposes Remote Desktop to the world."
}
func (firewallOpenRDP) Severity() ir.Severity { return ir.SeverityHigh }
func (firewallOpenRDP) AppliesTo(t string) bool {
	return t == "google_compute_firewall"
}
func (s firewallOpenRDP) Check(r ir.Resource) []ir.Finding {
	if _, _, ok := firewallTargetsWorld(r); !ok {
		return nil
	}
	blks, _, present, known := getBlocks(r, "allow")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		proto, _, pp, pk := getString(mapRes(b), "protocol")
		if !pp || !pk || strings.ToLower(proto) != "tcp" {
			continue
		}
		ports, span, ok := getStringList(mapRes(b), "ports")
		if !ok {
			continue
		}
		for _, p := range ports {
			if strings.TrimSpace(p) == "3389" {
				return []ir.Finding{mkFinding(s, r, "allow.ports", span,
					"3389 from 0.0.0.0/0", "restricted source ranges")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-068: Firewall allows all ports from the internet
type firewallAllPorts struct{}

func (firewallAllPorts) ID() string { return "AEGIS-GCP-068" }
func (firewallAllPorts) Title() string {
	return "Firewall allows all ports from the internet"
}
func (firewallAllPorts) Description() string {
	return "google_compute_firewall with an allow block covering ports " +
		"0-65535 (or 1-65535) from 0.0.0.0/0 exposes every service."
}
func (firewallAllPorts) Severity() ir.Severity { return ir.SeverityCritical }
func (firewallAllPorts) AppliesTo(t string) bool {
	return t == "google_compute_firewall"
}
func (s firewallAllPorts) Check(r ir.Resource) []ir.Finding {
	if _, _, ok := firewallTargetsWorld(r); !ok {
		return nil
	}
	blks, _, present, known := getBlocks(r, "allow")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		ports, span, ok := getStringList(mapRes(b), "ports")
		if !ok {
			continue
		}
		for _, p := range ports {
			tp := strings.TrimSpace(p)
			if tp == "0-65535" || tp == "1-65535" || tp == "0" {
				return []ir.Finding{mkFinding(s, r, "allow.ports", span,
					tp+" from 0.0.0.0/0", "specific required ports only")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-069: Firewall rule without logging
type firewallNoLogging struct{}

func (firewallNoLogging) ID() string { return "AEGIS-GCP-069" }
func (firewallNoLogging) Title() string {
	return "Firewall rule without flow logging"
}
func (firewallNoLogging) Description() string {
	return "google_compute_firewall with no log_config block produces no " +
		"audit trail of allowed/denied traffic."
}
func (firewallNoLogging) Severity() ir.Severity { return ir.SeverityMedium }
func (firewallNoLogging) AppliesTo(t string) bool {
	return t == "google_compute_firewall"
}
func (s firewallNoLogging) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBlocks(r, "log_config")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "log_config", r.Span,
			"absent", "log_config { metadata = \"INCLUDE_ALL_METADATA\" }")}
	}
	return nil
}

// AEGIS-GCP-070: Firewall allows all protocols
type firewallAllProtocols struct{}

func (firewallAllProtocols) ID() string { return "AEGIS-GCP-070" }
func (firewallAllProtocols) Title() string {
	return "Firewall allows all protocols"
}
func (firewallAllProtocols) Description() string {
	return "google_compute_firewall with an allow block for protocol \"all\" " +
		"permits every IP protocol through the rule."
}
func (firewallAllProtocols) Severity() ir.Severity { return ir.SeverityHigh }
func (firewallAllProtocols) AppliesTo(t string) bool {
	return t == "google_compute_firewall"
}
func (s firewallAllProtocols) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "allow")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		proto, span, p, k := getString(mapRes(b), "protocol")
		if p && k && strings.ToLower(strings.TrimSpace(proto)) == "all" {
			return []ir.Finding{mkFinding(s, r, "allow.protocol", span,
				"all", "specific protocols (tcp/udp/icmp)")}
		}
	}
	return nil
}

// AEGIS-GCP-071: Firewall egress allows all destinations
type firewallEgressAll struct{}

func (firewallEgressAll) ID() string { return "AEGIS-GCP-071" }
func (firewallEgressAll) Title() string {
	return "Firewall egress rule allows all destinations"
}
func (firewallEgressAll) Description() string {
	return "google_compute_firewall with direction EGRESS and " +
		"destination_ranges 0.0.0.0/0 allows unrestricted outbound traffic."
}
func (firewallEgressAll) Severity() ir.Severity { return ir.SeverityMedium }
func (firewallEgressAll) AppliesTo(t string) bool {
	return t == "google_compute_firewall"
}
func (s firewallEgressAll) Check(r ir.Resource) []ir.Finding {
	dir, _, dp, dk := getString(r, "direction")
	if !dp || !dk || strings.ToUpper(dir) != "EGRESS" {
		return nil
	}
	dests, span, ok := getStringList(r, "destination_ranges")
	if !ok {
		return nil
	}
	for _, d := range dests {
		if strings.TrimSpace(d) == "0.0.0.0/0" {
			return []ir.Finding{mkFinding(s, r, "destination_ranges", span,
				"0.0.0.0/0 on EGRESS", "restricted egress destinations")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// IAM: AEGIS-GCP-072..080
// ---------------------------------------------------------------------------

func iamBindingRole(r ir.Resource) (string, ir.Span, bool, bool) {
	return getString(r, "role")
}

func iamBindingHasPublicMember(r ir.Resource) (string, ir.Span, bool) {
	members, span, ok := getStringList(r, "members")
	if !ok {
		return "", ir.Span{}, false
	}
	for _, m := range members {
		lm := strings.ToLower(strings.TrimSpace(m))
		if lm == "allusers" || lm == "allauthenticatedusers" {
			return m, span, true
		}
	}
	return "", ir.Span{}, false
}

// AEGIS-GCP-072: Project IAM binding grants Owner
type iamOwnerBinding struct{}

func (iamOwnerBinding) ID() string { return "AEGIS-GCP-072" }
func (iamOwnerBinding) Title() string {
	return "Project IAM binding grants Owner role"
}
func (iamOwnerBinding) Description() string {
	return "google_project_iam_binding/member with roles/owner grants " +
		"full project control including IAM management."
}
func (iamOwnerBinding) Severity() ir.Severity { return ir.SeverityCritical }
func (iamOwnerBinding) AppliesTo(t string) bool {
	return t == "google_project_iam_binding" || t == "google_project_iam_member"
}
func (s iamOwnerBinding) Check(r ir.Resource) []ir.Finding {
	role, span, present, known := iamBindingRole(r)
	if !present || !known {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(role)) == "roles/owner" {
		return []ir.Finding{mkFinding(s, r, "role", span,
			role, "granular roles instead of roles/owner")}
	}
	return nil
}

// AEGIS-GCP-073: Project IAM binding grants Editor
type iamEditorBinding struct{}

func (iamEditorBinding) ID() string { return "AEGIS-GCP-073" }
func (iamEditorBinding) Title() string {
	return "Project IAM binding grants Editor role"
}
func (iamEditorBinding) Description() string {
	return "google_project_iam_binding/member with roles/editor grants " +
		"broad modify access across all project services."
}
func (iamEditorBinding) Severity() ir.Severity { return ir.SeverityHigh }
func (iamEditorBinding) AppliesTo(t string) bool {
	return t == "google_project_iam_binding" || t == "google_project_iam_member"
}
func (s iamEditorBinding) Check(r ir.Resource) []ir.Finding {
	role, span, present, known := iamBindingRole(r)
	if !present || !known {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(role)) == "roles/editor" {
		return []ir.Finding{mkFinding(s, r, "role", span,
			role, "granular roles instead of roles/editor")}
	}
	return nil
}

// AEGIS-GCP-074: Project IAM grants Viewer to a user
type iamViewerUser struct{}

func (iamViewerUser) ID() string { return "AEGIS-GCP-074" }
func (iamViewerUser) Title() string {
	return "Project IAM grants Viewer to individual user"
}
func (iamViewerUser) Description() string {
	return "google_project_iam_member with roles/viewer for user: identities " +
		"should use groups; hygiene finding."
}
func (iamViewerUser) Severity() ir.Severity { return ir.SeverityMedium }
func (iamViewerUser) AppliesTo(t string) bool {
	return t == "google_project_iam_member"
}
func (s iamViewerUser) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := iamBindingRole(r)
	if !present || !known {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(role)) != "roles/viewer" {
		return nil
	}
	member, span, mp, mk := getString(r, "member")
	if !mp || !mk {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(member), "user:") {
		return []ir.Finding{mkFinding(s, r, "member", span,
			member, "grant to group: identities instead")}
	}
	return nil
}

// AEGIS-GCP-075: Service account user-managed key
type saUserManagedKey struct{}

func (saUserManagedKey) ID() string { return "AEGIS-GCP-075" }
func (saUserManagedKey) Title() string {
	return "Service account with user-managed key"
}
func (saUserManagedKey) Description() string {
	return "google_service_account_key creates a long-lived downloadable " +
		"credential. Prefer workload identity federation."
}
func (saUserManagedKey) Severity() ir.Severity { return ir.SeverityHigh }
func (saUserManagedKey) AppliesTo(t string) bool {
	return t == "google_service_account_key"
}
func (s saUserManagedKey) Check(r ir.Resource) []ir.Finding {
	return []ir.Finding{mkFinding(s, r, "resource", r.Span,
		"user-managed service account key",
		"use workload identity federation instead of keys")}
}

// AEGIS-GCP-076: Project IAM member grants to the public
type iamMemberPublic struct{}

func (iamMemberPublic) ID() string { return "AEGIS-GCP-076" }
func (iamMemberPublic) Title() string {
	return "Project IAM grants role to the public"
}
func (iamMemberPublic) Description() string {
	return "google_project_iam_binding/member granting any role to " +
		"allUsers or allAuthenticatedUsers."
}
func (iamMemberPublic) Severity() ir.Severity { return ir.SeverityHigh }
func (iamMemberPublic) AppliesTo(t string) bool {
	return t == "google_project_iam_binding" || t == "google_project_iam_member"
}
func (s iamMemberPublic) Check(r ir.Resource) []ir.Finding {
	if m, span, ok := iamBindingHasPublicMember(r); ok {
		return []ir.Finding{mkFinding(s, r, "members", span,
			m, "remove public members")}
	}
	member, span, p, k := getString(r, "member")
	if p && k {
		lm := strings.ToLower(strings.TrimSpace(member))
		if lm == "allusers" || lm == "allauthenticatedusers" {
			return []ir.Finding{mkFinding(s, r, "member", span,
				member, "remove public member")}
		}
	}
	return nil
}

// AEGIS-GCP-077: Service account IAM binding grants to the public
type saIAMBindingPublic struct{}

func (saIAMBindingPublic) ID() string { return "AEGIS-GCP-077" }
func (saIAMBindingPublic) Title() string {
	return "Service account IAM grants to the public"
}
func (saIAMBindingPublic) Description() string {
	return "google_service_account_iam_binding/member granting roles to " +
		"allUsers/allAuthenticatedUsers lets anyone impersonate the " +
		"service account."
}
func (saIAMBindingPublic) Severity() ir.Severity { return ir.SeverityCritical }
func (saIAMBindingPublic) AppliesTo(t string) bool {
	return t == "google_service_account_iam_binding" ||
		t == "google_service_account_iam_member"
}
func (s saIAMBindingPublic) Check(r ir.Resource) []ir.Finding {
	if m, span, ok := iamBindingHasPublicMember(r); ok {
		return []ir.Finding{mkFinding(s, r, "members", span,
			m, "remove public members")}
	}
	member, span, p, k := getString(r, "member")
	if p && k {
		lm := strings.ToLower(strings.TrimSpace(member))
		if lm == "allusers" || lm == "allauthenticatedusers" {
			return []ir.Finding{mkFinding(s, r, "member", span,
				member, "remove public member")}
		}
	}
	return nil
}

// AEGIS-GCP-078: Custom IAM role with overly broad permissions
type customRoleBroad struct{}

func (customRoleBroad) ID() string { return "AEGIS-GCP-078" }
func (customRoleBroad) Title() string {
	return "Custom IAM role with wildcard permissions"
}
func (customRoleBroad) Description() string {
	return "google_project_iam_custom_role with permissions containing " +
		"\"*\" grants broader access than intended."
}
func (customRoleBroad) Severity() ir.Severity { return ir.SeverityMedium }
func (customRoleBroad) AppliesTo(t string) bool {
	return t == "google_project_iam_custom_role" ||
		t == "google_organization_iam_custom_role"
}
func (s customRoleBroad) Check(r ir.Resource) []ir.Finding {
	perms, span, ok := getStringList(r, "permissions")
	if !ok {
		return nil
	}
	for _, p := range perms {
		if strings.Contains(p, "*") {
			return []ir.Finding{mkFinding(s, r, "permissions", span,
				p, "explicit permission list without wildcards")}
		}
	}
	return nil
}

// AEGIS-GCP-079: Project without audit logging config
type iamNoAuditConfig struct{}

func (iamNoAuditConfig) ID() string { return "AEGIS-GCP-079" }
func (iamNoAuditConfig) Title() string {
	return "Project IAM policy without audit config"
}
func (iamNoAuditConfig) Description() string {
	return "google_project_iam_policy with no audit_config block has no " +
		"data-access audit logging configured."
}
func (iamNoAuditConfig) Severity() ir.Severity { return ir.SeverityMedium }
func (iamNoAuditConfig) AppliesTo(t string) bool {
	return t == "google_project_iam_policy"
}
func (s iamNoAuditConfig) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBlocks(r, "audit_config")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "audit_config", r.Span,
			"absent", "audit_config { audit_log_configs { log_type = \"DATA_READ\" } }")}
	}
	return nil
}

// AEGIS-GCP-080: Workload identity pool without OIDC attribute restriction
type workloadPoolNoOIDC struct{}

func (workloadPoolNoOIDC) ID() string { return "AEGIS-GCP-080" }
func (workloadPoolNoOIDC) Title() string {
	return "Workload identity pool without attribute restriction"
}
func (workloadPoolNoOIDC) Description() string {
	return "google_iam_workload_identity_pool_provider with no " +
		"attribute_condition accepts tokens from any subject in the OIDC " +
		"issuer."
}
func (workloadPoolNoOIDC) Severity() ir.Severity { return ir.SeverityMedium }
func (workloadPoolNoOIDC) AppliesTo(t string) bool {
	return t == "google_iam_workload_identity_pool_provider"
}
func (s workloadPoolNoOIDC) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "attribute_condition")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "attribute_condition", r.Span,
			"absent", "attribute_condition = \"assertion.repository == ...\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// KMS: AEGIS-GCP-081..084
// ---------------------------------------------------------------------------

// AEGIS-GCP-081: KMS key with rotation period over 90 days
type kmsLongRotation struct{}

func (kmsLongRotation) ID() string { return "AEGIS-GCP-081" }
func (kmsLongRotation) Title() string {
	return "KMS crypto key with rotation period over 90 days"
}
func (kmsLongRotation) Description() string {
	return "google_kms_crypto_key with rotation_period longer than 7776000s " +
		"(90 days) rotates too infrequently."
}
func (kmsLongRotation) Severity() ir.Severity { return ir.SeverityMedium }
func (kmsLongRotation) AppliesTo(t string) bool {
	return t == "google_kms_crypto_key"
}
func (s kmsLongRotation) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "rotation_period")
	if !present || !known {
		return nil // 012 covers absent rotation
	}
	secs := parseDurationSeconds(v)
	if secs < 0 {
		return nil
	}
	if secs > 7776000 {
		return []ir.Finding{mkFinding(s, r, "rotation_period", span,
			v, "rotation_period <= \"7776000s\" (90 days)")}
	}
	return nil
}

// parseDurationSeconds parses strings like "7776000s" to seconds.
func parseDurationSeconds(v string) int64 {
	v = strings.TrimSpace(strings.TrimSuffix(v, "s"))
	var n int64
	for _, c := range v {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

// AEGIS-GCP-082: KMS key IAM binding grants to the public
type kmsIAMPublic struct{}

func (kmsIAMPublic) ID() string { return "AEGIS-GCP-082" }
func (kmsIAMPublic) Title() string {
	return "KMS key IAM grants to the public"
}
func (kmsIAMPublic) Description() string {
	return "google_kms_crypto_key_iam_binding/member granting roles to " +
		"allUsers/allAuthenticatedUsers exposes key usage publicly."
}
func (kmsIAMPublic) Severity() ir.Severity { return ir.SeverityCritical }
func (kmsIAMPublic) AppliesTo(t string) bool {
	return t == "google_kms_crypto_key_iam_binding" ||
		t == "google_kms_crypto_key_iam_member" ||
		t == "google_kms_key_ring_iam_binding" ||
		t == "google_kms_key_ring_iam_member"
}
func (s kmsIAMPublic) Check(r ir.Resource) []ir.Finding {
	if m, span, ok := iamBindingHasPublicMember(r); ok {
		return []ir.Finding{mkFinding(s, r, "members", span,
			m, "remove public members")}
	}
	member, span, p, k := getString(r, "member")
	if p && k {
		lm := strings.ToLower(strings.TrimSpace(member))
		if lm == "allusers" || lm == "allauthenticatedusers" {
			return []ir.Finding{mkFinding(s, r, "member", span,
				member, "remove public member")}
		}
	}
	return nil
}

// AEGIS-GCP-083: KMS admin role granted to a user
type kmsAdminToUser struct{}

func (kmsAdminToUser) ID() string { return "AEGIS-GCP-083" }
func (kmsAdminToUser) Title() string {
	return "KMS admin role granted to individual user"
}
func (kmsAdminToUser) Description() string {
	return "google_kms_crypto_key_iam_member granting roles/cloudkms.admin " +
		"to user: identities should use groups."
}
func (kmsAdminToUser) Severity() ir.Severity { return ir.SeverityHigh }
func (kmsAdminToUser) AppliesTo(t string) bool {
	return t == "google_kms_crypto_key_iam_member"
}
func (s kmsAdminToUser) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(role)) != "roles/cloudkms.admin" {
		return nil
	}
	member, span, mp, mk := getString(r, "member")
	if !mp || !mk {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(member), "user:") {
		return []ir.Finding{mkFinding(s, r, "member", span,
			member, "grant to group: identities instead")}
	}
	return nil
}

// AEGIS-GCP-084: KMS key with weak algorithm
type kmsWeakAlgorithm struct{}

func (kmsWeakAlgorithm) ID() string { return "AEGIS-GCP-084" }
func (kmsWeakAlgorithm) Title() string {
	return "KMS crypto key with weak algorithm"
}
func (kmsWeakAlgorithm) Description() string {
	return "google_kms_crypto_key version_template with RSA 1024-bit or " +
		"SHA1-based algorithms is cryptographically weak."
}
func (kmsWeakAlgorithm) Severity() ir.Severity { return ir.SeverityMedium }
func (kmsWeakAlgorithm) AppliesTo(t string) bool {
	return t == "google_kms_crypto_key"
}
func (s kmsWeakAlgorithm) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "version_template")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		algo, span, p, k := getString(mapRes(b), "algorithm")
		if !p || !k {
			continue
		}
		ua := strings.ToUpper(algo)
		if strings.Contains(ua, "1024") || strings.Contains(ua, "SHA1") {
			return []ir.Finding{mkFinding(s, r, "version_template.algorithm", span,
				algo, "GOOGLE_SYMMETRIC_ENCRYPTION or RSA 2048+/SHA256")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Logging / project: AEGIS-GCP-085..090
// ---------------------------------------------------------------------------

// AEGIS-GCP-085: Logging sink without unique writer identity
type sinkNoUniqueWriter struct{}

func (sinkNoUniqueWriter) ID() string { return "AEGIS-GCP-085" }
func (sinkNoUniqueWriter) Title() string {
	return "Logging sink without unique writer identity"
}
func (sinkNoUniqueWriter) Description() string {
	return "google_logging_project_sink with unique_writer_identity = false " +
		"reuses a shared service account; hygiene finding."
}
func (sinkNoUniqueWriter) Severity() ir.Severity { return ir.SeverityLow }
func (sinkNoUniqueWriter) AppliesTo(t string) bool {
	return t == "google_logging_project_sink" ||
		t == "google_logging_folder_sink" ||
		t == "google_logging_organization_sink"
}
func (s sinkNoUniqueWriter) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["unique_writer_identity"]
	if !ok || !v.Known {
		return nil
	}
	if b, ok := v.AsBool(); ok && !b {
		return []ir.Finding{mkFinding(s, r, "unique_writer_identity", v.Span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-086: Audit config exempts allUsers from logging
type auditExemptAllUsers struct{}

func (auditExemptAllUsers) ID() string { return "AEGIS-GCP-086" }
func (auditExemptAllUsers) Title() string {
	return "Audit config exempts the public from logging"
}
func (auditExemptAllUsers) Description() string {
	return "google_project_iam_policy audit_config with exempted_members " +
		"containing allUsers/allAuthenticatedUsers blinds audit logs."
}
func (auditExemptAllUsers) Severity() ir.Severity { return ir.SeverityHigh }
func (auditExemptAllUsers) AppliesTo(t string) bool {
	return t == "google_project_iam_policy"
}
func (s auditExemptAllUsers) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "audit_config")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		lcs := blockList(b, "audit_log_configs")
		for _, lc := range lcs {
			members, span, ok := getStringList(mapRes(lc), "exempted_members")
			if !ok {
				continue
			}
			for _, m := range members {
				lm := strings.ToLower(strings.TrimSpace(m))
				if lm == "allusers" || lm == "allauthenticatedusers" {
					return []ir.Finding{mkFinding(s, r, "audit_log_configs.exempted_members",
						span, m, "remove public exemptions")}
				}
			}
		}
	}
	return nil
}

// AEGIS-GCP-087: Project without data-access audit logging
type auditNoDataRead struct{}

func (auditNoDataRead) ID() string { return "AEGIS-GCP-087" }
func (auditNoDataRead) Title() string {
	return "Project without data-access audit logging"
}
func (auditNoDataRead) Description() string {
	return "google_project_iam_policy audit_config with no audit_log_configs " +
		"entry for DATA_READ misses data access audit events."
}
func (auditNoDataRead) Severity() ir.Severity { return ir.SeverityMedium }
func (auditNoDataRead) AppliesTo(t string) bool {
	return t == "google_project_iam_policy"
}
func (s auditNoDataRead) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "audit_config")
	if !present || !known || len(blks) == 0 {
		return nil // 079 covers absent audit_config
	}
	for _, b := range blks {
		for _, lc := range blockList(b, "audit_log_configs") {
			lt, _, p, k := getString(mapRes(lc), "log_type")
			if p && k && strings.ToUpper(lt) == "DATA_READ" {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "audit_config.audit_log_configs", r.Span,
		"no DATA_READ log type", "audit_log_configs { log_type = \"DATA_READ\" }")}
}

// AEGIS-GCP-088: Project with auto-create default network
type projectAutoNetwork struct{}

func (projectAutoNetwork) ID() string { return "AEGIS-GCP-088" }
func (projectAutoNetwork) Title() string {
	return "Project auto-creates the default network"
}
func (projectAutoNetwork) Description() string {
	return "google_project with auto_create_network not false creates the " +
		"default VPC with permissive firewall rules."
}
func (projectAutoNetwork) Severity() ir.Severity { return ir.SeverityHigh }
func (projectAutoNetwork) AppliesTo(t string) bool {
	return t == "google_project"
}
func (s projectAutoNetwork) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["auto_create_network"]
	if !ok {
		// absent: provider default is true
		return []ir.Finding{mkFinding(s, r, "auto_create_network", r.Span,
			"absent (defaults to true)", "auto_create_network = false")}
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	if b, ok := v.AsBool(); ok && b {
		return []ir.Finding{mkFinding(s, r, "auto_create_network", v.Span,
			"true", "false")}
	}
	return nil
}

// AEGIS-GCP-089: Project metadata without OS Login
type projectMetadataNoOSLogin struct{}

func (projectMetadataNoOSLogin) ID() string { return "AEGIS-GCP-089" }
func (projectMetadataNoOSLogin) Title() string {
	return "Project metadata without OS Login enabled"
}
func (projectMetadataNoOSLogin) Description() string {
	return "google_compute_project_metadata with metadata enable-oslogin not " +
		"TRUE leaves SSH to project-wide keys."
}
func (projectMetadataNoOSLogin) Severity() ir.Severity { return ir.SeverityMedium }
func (projectMetadataNoOSLogin) AppliesTo(t string) bool {
	return t == "google_compute_project_metadata"
}
func (s projectMetadataNoOSLogin) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["metadata"]
	if !ok || !v.Known {
		return nil
	}
	m, ok := v.AsMap()
	if !ok {
		return nil
	}
	ov, ok := m["enable-oslogin"]
	if !ok || !ov.Known {
		return nil
	}
	if sv, ok := ov.AsString(); ok && strings.ToUpper(sv) != "TRUE" {
		return []ir.Finding{mkFinding(s, r, "metadata.enable-oslogin", ov.Span,
			sv, "TRUE")}
	}
	return nil
}

// AEGIS-GCP-090: Logging sink without filter
type logSinkNoFilter struct{}

func (logSinkNoFilter) ID() string { return "AEGIS-GCP-090" }
func (logSinkNoFilter) Title() string {
	return "Logging sink without filter exports everything"
}
func (logSinkNoFilter) Description() string {
	return "google_logging_project_sink with no filter exports all logs, " +
		"increasing cost and noise; hygiene finding."
}
func (logSinkNoFilter) Severity() ir.Severity { return ir.SeverityLow }
func (logSinkNoFilter) AppliesTo(t string) bool {
	return t == "google_logging_project_sink"
}
func (s logSinkNoFilter) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "filter")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "filter", r.Span,
			"absent (exports all logs)", "filter = \"severity >= WARNING\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// DNS: AEGIS-GCP-091..093
// ---------------------------------------------------------------------------

// AEGIS-GCP-091: DNS policy without query logging
type dnsPolicyNoLogging struct{}

func (dnsPolicyNoLogging) ID() string { return "AEGIS-GCP-091" }
func (dnsPolicyNoLogging) Title() string {
	return "DNS policy without query logging"
}
func (dnsPolicyNoLogging) Description() string {
	return "google_dns_policy with enable_logging not true produces no " +
		"DNS query audit trail."
}
func (dnsPolicyNoLogging) Severity() ir.Severity { return ir.SeverityMedium }
func (dnsPolicyNoLogging) AppliesTo(t string) bool {
	return t == "google_dns_policy"
}
func (s dnsPolicyNoLogging) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["enable_logging"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "enable_logging", r.Span,
			"absent", "enable_logging = true")}
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	if b, ok := v.AsBool(); ok && !b {
		return []ir.Finding{mkFinding(s, r, "enable_logging", v.Span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-092: DNS wildcard record
type dnsWildcardRecord struct{}

func (dnsWildcardRecord) ID() string { return "AEGIS-GCP-092" }
func (dnsWildcardRecord) Title() string {
	return "DNS record with wildcard name"
}
func (dnsWildcardRecord) Description() string {
	return "google_dns_record_set with a wildcard (*) name can be abused " +
		"for subdomain takeover patterns."
}
func (dnsWildcardRecord) Severity() ir.Severity { return ir.SeverityMedium }
func (dnsWildcardRecord) AppliesTo(t string) bool {
	return t == "google_dns_record_set"
}
func (s dnsWildcardRecord) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "name")
	if !present || !known {
		return nil
	}
	if strings.Contains(v, "*") {
		return []ir.Finding{mkFinding(s, r, "name", span,
			v, "explicit record names")}
	}
	return nil
}

// AEGIS-GCP-093: DNSSEC with weak algorithm
type dnsWeakDNSSEC struct{}

func (dnsWeakDNSSEC) ID() string { return "AEGIS-GCP-093" }
func (dnsWeakDNSSEC) Title() string {
	return "DNSSEC with weak signing algorithm"
}
func (dnsWeakDNSSEC) Description() string {
	return "google_dns_managed_zone dnssec_config with RSASHA1 algorithms " +
		"uses deprecated weak DNSSEC signing."
}
func (dnsWeakDNSSEC) Severity() ir.Severity { return ir.SeverityMedium }
func (dnsWeakDNSSEC) AppliesTo(t string) bool {
	return t == "google_dns_managed_zone"
}
func (s dnsWeakDNSSEC) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "dnssec_config")
	if !present || !known {
		return nil // 024 covers absent DNSSEC
	}
	for _, b := range blks {
		for _, kk := range blockList(b, "default_key_specs") {
			algo, span, p, k := getString(mapRes(kk), "algorithm")
			if !p || !k {
				continue
			}
			if strings.Contains(strings.ToLower(algo), "rsasha1") {
				return []ir.Finding{mkFinding(s, r, "dnssec_config.default_key_specs.algorithm",
					span, algo, "rsasha256 or ecdsap256sha256")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Pub/Sub: AEGIS-GCP-094..096
// ---------------------------------------------------------------------------

// AEGIS-GCP-094: Pub/Sub topic without message retention
type pubsubNoRetention struct{}

func (pubsubNoRetention) ID() string { return "AEGIS-GCP-094" }
func (pubsubNoRetention) Title() string {
	return "Pub/Sub topic without message retention"
}
func (pubsubNoRetention) Description() string {
	return "google_pubsub_topic with no message_retention_duration loses " +
		"unacknowledged messages after 7 days default; hygiene finding."
}
func (pubsubNoRetention) Severity() ir.Severity { return ir.SeverityLow }
func (pubsubNoRetention) AppliesTo(t string) bool {
	return t == "google_pubsub_topic"
}
func (s pubsubNoRetention) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "message_retention_duration")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "message_retention_duration", r.Span,
			"absent", "message_retention_duration = \"86400s\"")}
	}
	return nil
}

// AEGIS-GCP-095: Pub/Sub subscription without dead letter policy
type pubsubNoDeadLetter struct{}

func (pubsubNoDeadLetter) ID() string { return "AEGIS-GCP-095" }
func (pubsubNoDeadLetter) Title() string {
	return "Pub/Sub subscription without dead letter policy"
}
func (pubsubNoDeadLetter) Description() string {
	return "google_pubsub_subscription with no dead_letter_policy drops " +
		"poison messages silently; hygiene finding."
}
func (pubsubNoDeadLetter) Severity() ir.Severity { return ir.SeverityLow }
func (pubsubNoDeadLetter) AppliesTo(t string) bool {
	return t == "google_pubsub_subscription"
}
func (s pubsubNoDeadLetter) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBlocks(r, "dead_letter_policy")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "dead_letter_policy", r.Span,
			"absent", "dead_letter_policy { dead_letter_topic = ... }")}
	}
	return nil
}

// AEGIS-GCP-096: Pub/Sub topic IAM grants to the public
type pubsubTopicPublic struct{}

func (pubsubTopicPublic) ID() string { return "AEGIS-GCP-096" }
func (pubsubTopicPublic) Title() string {
	return "Pub/Sub topic IAM grants to the public"
}
func (pubsubTopicPublic) Description() string {
	return "google_pubsub_topic_iam_binding/member granting publish or " +
		"subscribe to allUsers/allAuthenticatedUsers."
}
func (pubsubTopicPublic) Severity() ir.Severity { return ir.SeverityCritical }
func (pubsubTopicPublic) AppliesTo(t string) bool {
	return t == "google_pubsub_topic_iam_binding" ||
		t == "google_pubsub_topic_iam_member"
}
func (s pubsubTopicPublic) Check(r ir.Resource) []ir.Finding {
	if m, span, ok := iamBindingHasPublicMember(r); ok {
		return []ir.Finding{mkFinding(s, r, "members", span,
			m, "remove public members")}
	}
	member, span, p, k := getString(r, "member")
	if p && k {
		lm := strings.ToLower(strings.TrimSpace(member))
		if lm == "allusers" || lm == "allauthenticatedusers" {
			return []ir.Finding{mkFinding(s, r, "member", span,
				member, "remove public member")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Cloud Functions / Cloud Run: AEGIS-GCP-097..100
// ---------------------------------------------------------------------------

// AEGIS-GCP-097: Cloud Run service IAM grants public invoker
type cloudRunPublic struct{}

func (cloudRunPublic) ID() string { return "AEGIS-GCP-097" }
func (cloudRunPublic) Title() string {
	return "Cloud Run service allows public invocation"
}
func (cloudRunPublic) Description() string {
	return "google_cloud_run_service_iam_binding/member granting " +
		"roles/run.invoker to allUsers/allAuthenticatedUsers exposes the " +
		"service publicly."
}
func (cloudRunPublic) Severity() ir.Severity { return ir.SeverityHigh }
func (cloudRunPublic) AppliesTo(t string) bool {
	return t == "google_cloud_run_service_iam_binding" ||
		t == "google_cloud_run_service_iam_member" ||
		t == "google_cloud_run_v2_service_iam_binding" ||
		t == "google_cloud_run_v2_service_iam_member"
}
func (s cloudRunPublic) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil
	}
	if !strings.Contains(strings.ToLower(role), "run.invoker") {
		return nil
	}
	if m, span, ok := iamBindingHasPublicMember(r); ok {
		return []ir.Finding{mkFinding(s, r, "members", span,
			m, "remove public invokers")}
	}
	member, span, p, k := getString(r, "member")
	if p && k {
		lm := strings.ToLower(strings.TrimSpace(member))
		if lm == "allusers" || lm == "allauthenticatedusers" {
			return []ir.Finding{mkFinding(s, r, "member", span,
				member, "remove public invoker")}
		}
	}
	return nil
}

// AEGIS-GCP-098: Cloud Function without max instances
type functionNoMaxInstances struct{}

func (functionNoMaxInstances) ID() string { return "AEGIS-GCP-098" }
func (functionNoMaxInstances) Title() string {
	return "Cloud Function without max instance limit"
}
func (functionNoMaxInstances) Description() string {
	return "google_cloudfunctions_function with no max_instances can " +
		"scale without bound on cost or DoS; hygiene finding."
}
func (functionNoMaxInstances) Severity() ir.Severity { return ir.SeverityLow }
func (functionNoMaxInstances) AppliesTo(t string) bool {
	return t == "google_cloudfunctions_function" ||
		t == "google_cloudfunctions2_function"
}
func (s functionNoMaxInstances) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "max_instances")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "max_instances", r.Span,
			"absent (unbounded)", "max_instances = 10")}
	}
	return nil
}

// AEGIS-GCP-099: Cloud Run service with default service account
type cloudRunDefaultSA struct{}

func (cloudRunDefaultSA) ID() string { return "AEGIS-GCP-099" }
func (cloudRunDefaultSA) Title() string {
	return "Cloud Run service with default service account"
}
func (cloudRunDefaultSA) Description() string {
	return "google_cloud_run_service template spec without " +
		"service_account_name uses the default Compute service account."
}
func (cloudRunDefaultSA) Severity() ir.Severity { return ir.SeverityMedium }
func (cloudRunDefaultSA) AppliesTo(t string) bool {
	return t == "google_cloud_run_service" || t == "google_cloud_run_v2_service"
}
func (s cloudRunDefaultSA) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "template")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		specs := blockList(b, "spec")
		if len(specs) == 0 {
			// v2 shape: template.containers directly
			sa, _, p, k := getString(mapRes(b), "service_account")
			if !p || !k || strings.TrimSpace(sa) == "" {
				return []ir.Finding{mkFinding(s, r, "template.service_account", r.Span,
					"default service account", "dedicated least-privilege SA")}
			}
			continue
		}
		for _, sp := range specs {
			sa, _, p, k := getString(mapRes(sp), "service_account_name")
			if !p || !k || strings.TrimSpace(sa) == "" {
				return []ir.Finding{mkFinding(s, r, "template.spec.service_account_name",
					r.Span, "default service account",
					"dedicated least-privilege SA")}
			}
		}
	}
	return nil
}

// AEGIS-GCP-100: Cloud Function source from public bucket
type functionPublicSource struct{}

func (functionPublicSource) ID() string { return "AEGIS-GCP-100" }
func (functionPublicSource) Title() string {
	return "Cloud Function source code in public bucket"
}
func (functionPublicSource) Description() string {
	return "google_cloudfunctions_function with source_archive_bucket " +
		"referencing a publicly readable bucket exposes function source."
}
func (functionPublicSource) Severity() ir.Severity { return ir.SeverityMedium }
func (functionPublicSource) AppliesTo(t string) bool {
	return t == "google_cloudfunctions_function"
}
func (s functionPublicSource) Check(r ir.Resource) []ir.Finding {
	// Heuristic: bucket name containing "public" is a smell; the definitive
	// check (bucket ACL) is covered by AEGIS-GCP-026. Flag only when the
	// source bucket is explicitly marked public via a companion attribute.
	// Conservative: only fire when source_archive_bucket name suggests public.
	bkt, span, present, known := getString(r, "source_archive_bucket")
	if !present || !known {
		return nil
	}
	if strings.Contains(strings.ToLower(bkt), "public") {
		return []ir.Finding{mkFinding(s, r, "source_archive_bucket", span,
			bkt, "private source bucket with restricted IAM")}
	}
	return nil
}
