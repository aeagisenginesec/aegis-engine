// Package gcp — expansion round 6 (AEGIS-GCP-143..182).
//
// Fills thin areas: IAM (service-account keys, org/folder IAM, authoritative
// policies, deleted principals, impersonation), Cloud SQL (Query Insights,
// HA, password handling, retention, binary log, SSL mode), GKE (security
// posture, legacy metadata endpoints, etcd encryption, authenticator groups,
// alpha clusters, VPC-native, external IPs, open master networks, boot-disk
// CMEK), and Compute (confidential VM, vTPM, integrity monitoring, OS Login
// 2FA, instance templates, snapshot/image CMEK).
//
// Every candidate in the brief that already had an equivalent rule in
// gcp2.go/gcp3.go/gcp4.go/gcp5.go was dropped in favour of a distinct check:
// user-managed SA keys (075), basic project roles (072/073), public project
// IAM (076), SA IAM public (077), KMS rotation (012), SQL PITR (039), SQL
// deletion protection (019), SQL open authorized networks (040), SQL IAM auth
// (044), SQL maintenance window (042), GKE workload identity (047), GKE
// confidential nodes (056), GKE legacy ABAC (009), GKE client cert (052),
// instance full scope (018/063), IP forwarding (057/118), instance deletion
// protection (064), OS Login (060), serial port (058/119), private Google
// access (023), DNSSEC (024), DNS policy logging (091), require_ssl (008),
// GKE private cluster (011), GKE release channel (114), WIF attribute
// condition (080), custom-role wildcard (078), GKE logging (021),
// boot-disk CMEK (061), block-project-ssh-keys (065), default SA (062),
// GKE private endpoint (113).
//
// Absent-attribute policy: an absent attribute yields a finding only when
// the provider default is the insecure one; present-but-unresolved values
// yield NO finding. Rules never panic on unexpected shapes.
package gcp

import (
	"strconv"
	"strings"
	"time"

	"aegis/internal/ir"
)

// GCP6Rules returns GCP expansion rules 143..182 in ID order.
func GCP6Rules() []ir.Rule {
	return []ir.Rule{
		saKeyExpired{},                    // AEGIS-GCP-143
		saUntracked{},                     // AEGIS-GCP-144
		saKeyWeakAlgorithm{},              // AEGIS-GCP-145
		saImpersonationBroadGrant{},       // AEGIS-GCP-146
		projectIamAuthoritativePolicy{},   // AEGIS-GCP-147
		orgIamBasicRoles{},                // AEGIS-GCP-148
		folderIamBasicRoles{},             // AEGIS-GCP-149
		iamDeletedPrincipal{},             // AEGIS-GCP-150
		saIamAuthoritativePolicy{},        // AEGIS-GCP-151
		iamProjectIamAdminGrant{},         // AEGIS-GCP-152
		sqlNoQueryInsights{},              // AEGIS-GCP-153
		sqlNotHighlyAvailable{},           // AEGIS-GCP-154
		sqlUserPasswordInConfig{},         // AEGIS-GCP-155
		sqlLowBackupRetention{},           // AEGIS-GCP-156
		sqlNoPasswordValidationPolicy{},   // AEGIS-GCP-157
		sqlRootPasswordInConfig{},         // AEGIS-GCP-158
		sqlShortTransactionLogRetention{}, // AEGIS-GCP-159
		sqlNoBinaryLog{},                  // AEGIS-GCP-160
		sqlWeakPasswordEncryption{},       // AEGIS-GCP-161
		sqlSSLModePermissive{},            // AEGIS-GCP-162
		gkeNoSecurityPosture{},            // AEGIS-GCP-163
		gkeLegacyMetadataEndpoints{},      // AEGIS-GCP-164
		gkeNoDatabaseEncryption{},         // AEGIS-GCP-165
		gkeNoAuthenticatorGroups{},        // AEGIS-GCP-166
		gkeAlphaCluster{},                 // AEGIS-GCP-167
		gkeNoVPCNative{},                  // AEGIS-GCP-168
		gkeServiceExternalIPs{},           // AEGIS-GCP-169
		gkeMasterAuthNetworksOpen{},       // AEGIS-GCP-170
		gkeNodePoolLegacyMetadata{},       // AEGIS-GCP-171
		gkeNodeBootDiskNoCMEK{},           // AEGIS-GCP-172
		computeNoConfidentialVM{},         // AEGIS-GCP-173
		computeVTPMOff{},                  // AEGIS-GCP-174
		computeIntegrityMonOff{},          // AEGIS-GCP-175
		computeNoOSLogin2FA{},             // AEGIS-GCP-176
		instanceTemplateNoSecureBoot{},    // AEGIS-GCP-177
		instanceTemplatePublicIP{},        // AEGIS-GCP-178
		instanceTemplateNoOSLogin{},       // AEGIS-GCP-179
		instanceTemplateSerialPort{},      // AEGIS-GCP-180
		snapshotNoCMEK{},                  // AEGIS-GCP-181
		imageNoCMEK{},                     // AEGIS-GCP-182
	}
}

// ---------------------------------------------------------------------------
// Shared helpers for round 6
// ---------------------------------------------------------------------------

// topMetaString reads key from a top-level metadata map attribute
// (google_compute_instance / google_compute_instance_template).
func topMetaString(r ir.Resource, key string) (val string, span ir.Span, present, known bool) {
	v, ok := r.Attributes["metadata"]
	if !ok {
		return "", ir.Span{}, false, false
	}
	if !v.Known {
		return "", v.Span, true, false
	}
	m, ok := v.AsMap()
	if !ok {
		return "", v.Span, true, false
	}
	kv, ok := m[key]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := kv.AsString()
	return s, kv.Span, true, kok
}

// nodeConfigMetaString reads key from node_config.metadata on GKE clusters
// and node pools.
func nodeConfigMetaString(r ir.Resource, key string) (val string, span ir.Span, present, known bool) {
	blks, _, bpresent, bknown := getBlocks(r, "node_config")
	if !bpresent {
		return "", ir.Span{}, false, false
	}
	if !bknown {
		return "", ir.Span{}, true, false // node_config unresolved: cannot decide
	}
	for _, b := range blks {
		v, ok := b["metadata"]
		if !ok {
			continue
		}
		if !v.Known {
			return "", v.Span, true, false // metadata unresolved: cannot decide
		}
		m, ok := v.AsMap()
		if !ok {
			return "", v.Span, true, false // unexpected shape: cannot decide
		}
		kv, ok := m[key]
		if !ok {
			continue
		}
		s, kok := kv.AsString()
		return s, kv.Span, true, kok
	}
	return "", ir.Span{}, false, false
}

// blockNum extracts a numeric leaf from a block map (tri-state).
func blockNum(m map[string]ir.Value, name string) (float64, bool, bool) {
	v, ok := m[name]
	if !ok {
		return 0, false, false
	}
	if !v.Known {
		return 0, true, false
	}
	f, ok := v.Raw.(float64)
	if !ok {
		return 0, true, false
	}
	return f, true, true
}

// sqlSettings returns the settings blocks of a Cloud SQL instance.
func sqlSettings(r ir.Resource) ([]map[string]ir.Value, ir.Span, bool, bool) {
	return getBlocks(r, "settings")
}

// sqlBackupConfig returns the backup_configuration blocks under settings.
func sqlBackupConfig(st map[string]ir.Value) []map[string]ir.Value {
	return blockList(st, "backup_configuration")
}

// isBasicRole reports whether role is a GCP primitive (basic) role.
func isBasicRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "roles/owner", "roles/editor", "roles/viewer":
		return true
	}
	return false
}

// iamMembersCollect gathers member identities from a binding/member resource.
// Returns the matched member, its span, and whether any member list/member
// was present and fully known.
func iamMembersCollect(r ir.Resource, match func(string) bool) (string, ir.Span, bool) {
	if members, span, ok := getStringList(r, "members"); ok {
		for _, m := range members {
			if match(m) {
				return m, span, true
			}
		}
		return "", ir.Span{}, true // members known, none matched
	}
	if member, span, p, k := getString(r, "member"); p && k {
		if match(member) {
			return member, span, true
		}
		return "", ir.Span{}, true
	}
	return "", ir.Span{}, false // absent or unresolved: cannot decide
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-143: Service account key past its validity window
// ---------------------------------------------------------------------------

type saKeyExpired struct{}

func (saKeyExpired) ID() string { return "AEGIS-GCP-143" }
func (saKeyExpired) Title() string {
	return "Service account key expired or past validity"
}
func (saKeyExpired) Description() string {
	return "google_service_account_key with valid_before in the past is " +
		"expired (or was issued long ago and never rotated). Rotate " +
		"service account keys at least every 90 days; prefer workload " +
		"identity federation over long-lived keys."
}
func (saKeyExpired) Severity() ir.Severity { return ir.SeverityMedium }

func (saKeyExpired) AppliesTo(resType string) bool {
	return resType == "google_service_account_key"
}

func (s saKeyExpired) Check(r ir.Resource) []ir.Finding {
	vb, span, present, known := getString(r, "valid_before")
	if !present || !known {
		return nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(vb))
	if err != nil {
		return nil // unparseable timestamp: cannot decide
	}
	if t.Before(time.Now()) {
		return []ir.Finding{mkFinding(s, r, "valid_before", span, vb,
			"valid_before in the future; rotate keys at least every 90 days")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-144: Service account without display name or description
// ---------------------------------------------------------------------------

type saUntracked struct{}

func (saUntracked) ID() string { return "AEGIS-GCP-144" }
func (saUntracked) Title() string {
	return "Service account without display name or description"
}
func (saUntracked) Description() string {
	return "google_service_account with neither display_name nor " +
		"description is untracked inventory: ownership and purpose cannot " +
		"be determined during incident response or access reviews. Label " +
		"every service account."
}
func (saUntracked) Severity() ir.Severity { return ir.SeverityLow }

func (saUntracked) AppliesTo(resType string) bool {
	return resType == "google_service_account"
}

func (s saUntracked) Check(r ir.Resource) []ir.Finding {
	for _, attr := range []string{"display_name", "description"} {
		v, _, present, known := getString(r, attr)
		if present && !known {
			return nil // unresolved: cannot decide
		}
		if present && strings.TrimSpace(v) != "" {
			return nil // labelled
		}
	}
	return []ir.Finding{mkFinding(s, r, "display_name", ir.Span{},
		"absent (no display_name or description)",
		"display_name = \"<owner/purpose>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-145: Service account key with weak RSA-1024 algorithm
// ---------------------------------------------------------------------------

type saKeyWeakAlgorithm struct{}

func (saKeyWeakAlgorithm) ID() string { return "AEGIS-GCP-145" }
func (saKeyWeakAlgorithm) Title() string {
	return "Service account key using weak RSA-1024 algorithm"
}
func (saKeyWeakAlgorithm) Description() string {
	return "google_service_account_key with key_algorithm = " +
		"\"KEY_ALG_RSA_1024\" uses 1024-bit RSA, below the minimum safe " +
		"strength. Use KEY_ALG_RSA_2048 (the default) or stronger."
}
func (saKeyWeakAlgorithm) Severity() ir.Severity { return ir.SeverityHigh }

func (saKeyWeakAlgorithm) AppliesTo(resType string) bool {
	return resType == "google_service_account_key"
}

func (s saKeyWeakAlgorithm) Check(r ir.Resource) []ir.Finding {
	algo, span, present, known := getString(r, "key_algorithm")
	if !present || !known {
		return nil // default is RSA-2048
	}
	if strings.EqualFold(strings.TrimSpace(algo), "KEY_ALG_RSA_1024") {
		return []ir.Finding{mkFinding(s, r, "key_algorithm", span, algo,
			"key_algorithm = \"KEY_ALG_RSA_2048\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-146: Service account impersonation granted broadly
// ---------------------------------------------------------------------------

type saImpersonationBroadGrant struct{}

func (saImpersonationBroadGrant) ID() string { return "AEGIS-GCP-146" }
func (saImpersonationBroadGrant) Title() string {
	return "Service account impersonation granted to a broad group"
}
func (saImpersonationBroadGrant) Description() string {
	return "google_project_iam_binding/member granting " +
		"roles/iam.serviceAccountTokenCreator to a group: or domain: " +
		"principal lets many identities mint short-lived tokens for " +
		"service accounts. Scope impersonation to named service accounts."
}
func (saImpersonationBroadGrant) Severity() ir.Severity { return ir.SeverityHigh }

func (saImpersonationBroadGrant) AppliesTo(resType string) bool {
	return resType == "google_project_iam_binding" ||
		resType == "google_project_iam_member"
}

func isBroadImpersonationMember(m string) bool {
	lm := strings.ToLower(strings.TrimSpace(m))
	return strings.HasPrefix(lm, "group:") || strings.HasPrefix(lm, "domain:")
}

func (s saImpersonationBroadGrant) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(role), "roles/iam.serviceAccountTokenCreator") {
		return nil
	}
	m, span, decided := iamMembersCollect(r, isBroadImpersonationMember)
	if !decided {
		return nil
	}
	if m == "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "members", span, m,
		"grant roles/iam.serviceAccountTokenCreator to named service accounts only")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-147: Authoritative project IAM policy
// ---------------------------------------------------------------------------

type projectIamAuthoritativePolicy struct{}

func (projectIamAuthoritativePolicy) ID() string { return "AEGIS-GCP-147" }
func (projectIamAuthoritativePolicy) Title() string {
	return "Authoritative project IAM policy replaces all bindings"
}
func (projectIamAuthoritativePolicy) Description() string {
	return "google_project_iam_policy is authoritative: applying it " +
		"replaces the entire project IAM policy, silently removing " +
		"bindings managed elsewhere. Prefer google_project_iam_binding " +
		"or google_project_iam_member."
}
func (projectIamAuthoritativePolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (projectIamAuthoritativePolicy) AppliesTo(resType string) bool {
	return resType == "google_project_iam_policy"
}

func (s projectIamAuthoritativePolicy) Check(r ir.Resource) []ir.Finding {
	return []ir.Finding{mkFinding(s, r, "resource", r.Span,
		"google_project_iam_policy present (authoritative)",
		"use google_project_iam_binding/member instead")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-148: Organization IAM grants basic roles
// ---------------------------------------------------------------------------

type orgIamBasicRoles struct{}

func (orgIamBasicRoles) ID() string { return "AEGIS-GCP-148" }
func (orgIamBasicRoles) Title() string {
	return "Organization IAM grants primitive basic roles"
}
func (orgIamBasicRoles) Description() string {
	return "google_organization_iam_binding/member granting roles/owner, " +
		"roles/editor, or roles/viewer confers project-wide primitive " +
		"power across every project in the organization. Grant granular " +
		"roles at the project or folder level instead."
}
func (orgIamBasicRoles) Severity() ir.Severity { return ir.SeverityCritical }

func (orgIamBasicRoles) AppliesTo(resType string) bool {
	return resType == "google_organization_iam_binding" ||
		resType == "google_organization_iam_member"
}

func (s orgIamBasicRoles) Check(r ir.Resource) []ir.Finding {
	role, span, present, known := iamBindingRole(r)
	if !present || !known {
		return nil
	}
	if isBasicRole(role) {
		return []ir.Finding{mkFinding(s, r, "role", span, role,
			"granular roles instead of primitive basic roles")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-149: Folder IAM grants basic roles
// ---------------------------------------------------------------------------

type folderIamBasicRoles struct{}

func (folderIamBasicRoles) ID() string { return "AEGIS-GCP-149" }
func (folderIamBasicRoles) Title() string {
	return "Folder IAM grants primitive basic roles"
}
func (folderIamBasicRoles) Description() string {
	return "google_folder_iam_binding/member granting roles/owner, " +
		"roles/editor, or roles/viewer confers primitive power across " +
		"every project in the folder. Grant granular roles at the " +
		"project level instead."
}
func (folderIamBasicRoles) Severity() ir.Severity { return ir.SeverityHigh }

func (folderIamBasicRoles) AppliesTo(resType string) bool {
	return resType == "google_folder_iam_binding" ||
		resType == "google_folder_iam_member"
}

func (s folderIamBasicRoles) Check(r ir.Resource) []ir.Finding {
	role, span, present, known := iamBindingRole(r)
	if !present || !known {
		return nil
	}
	if isBasicRole(role) {
		return []ir.Finding{mkFinding(s, r, "role", span, role,
			"granular roles instead of primitive basic roles")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-150: IAM binding references a deleted principal
// ---------------------------------------------------------------------------

type iamDeletedPrincipal struct{}

func (iamDeletedPrincipal) ID() string { return "AEGIS-GCP-150" }
func (iamDeletedPrincipal) Title() string {
	return "IAM binding references a deleted principal"
}
func (iamDeletedPrincipal) Description() string {
	return "An IAM binding/member granting a role to a deleted: principal " +
		"is stale access residue: the identity no longer exists, but the " +
		"grant lingers and a recreated identity could inherit it. Remove " +
		"deleted principals from IAM policy."
}
func (iamDeletedPrincipal) Severity() ir.Severity { return ir.SeverityLow }

func (iamDeletedPrincipal) AppliesTo(resType string) bool {
	switch resType {
	case "google_project_iam_binding", "google_project_iam_member",
		"google_folder_iam_binding", "google_folder_iam_member",
		"google_organization_iam_binding", "google_organization_iam_member":
		return true
	}
	return false
}

func isDeletedPrincipal(m string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(m)), "deleted:")
}

func (s iamDeletedPrincipal) Check(r ir.Resource) []ir.Finding {
	m, span, decided := iamMembersCollect(r, isDeletedPrincipal)
	if !decided {
		return nil
	}
	if m == "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "members", span, m,
		"remove deleted principals from the binding")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-151: Authoritative service account IAM policy
// ---------------------------------------------------------------------------

type saIamAuthoritativePolicy struct{}

func (saIamAuthoritativePolicy) ID() string { return "AEGIS-GCP-151" }
func (saIamAuthoritativePolicy) Title() string {
	return "Authoritative service account IAM policy replaces all bindings"
}
func (saIamAuthoritativePolicy) Description() string {
	return "google_service_account_iam_policy is authoritative: applying " +
		"it replaces the entire IAM policy on the service account, " +
		"silently removing bindings managed elsewhere (including " +
		"impersonation grants). Prefer google_service_account_iam_binding " +
		"or google_service_account_iam_member."
}
func (saIamAuthoritativePolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (saIamAuthoritativePolicy) AppliesTo(resType string) bool {
	return resType == "google_service_account_iam_policy"
}

func (s saIamAuthoritativePolicy) Check(r ir.Resource) []ir.Finding {
	return []ir.Finding{mkFinding(s, r, "resource", r.Span,
		"google_service_account_iam_policy present (authoritative)",
		"use google_service_account_iam_binding/member instead")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-152: Project IAM grants Project IAM Admin
// ---------------------------------------------------------------------------

type iamProjectIamAdminGrant struct{}

func (iamProjectIamAdminGrant) ID() string { return "AEGIS-GCP-152" }
func (iamProjectIamAdminGrant) Title() string {
	return "Project IAM grants Project IAM Admin role"
}
func (iamProjectIamAdminGrant) Description() string {
	return "google_project_iam_binding/member with " +
		"roles/resourcemanager.projectIamAdmin can rewrite project IAM " +
		"policy, granting itself any role. Restrict this role to break-glass " +
		"administrators."
}
func (iamProjectIamAdminGrant) Severity() ir.Severity { return ir.SeverityHigh }

func (iamProjectIamAdminGrant) AppliesTo(resType string) bool {
	return resType == "google_project_iam_binding" ||
		resType == "google_project_iam_member"
}

func (s iamProjectIamAdminGrant) Check(r ir.Resource) []ir.Finding {
	role, span, present, known := iamBindingRole(r)
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(role), "roles/resourcemanager.projectIamAdmin") {
		return []ir.Finding{mkFinding(s, r, "role", span, role,
			"restrict roles/resourcemanager.projectIamAdmin to break-glass admins")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-153: Cloud SQL without Query Insights
// ---------------------------------------------------------------------------

type sqlNoQueryInsights struct{}

func (sqlNoQueryInsights) ID() string { return "AEGIS-GCP-153" }
func (sqlNoQueryInsights) Title() string {
	return "Cloud SQL instance without Query Insights"
}
func (sqlNoQueryInsights) Description() string {
	return "google_sql_database_instance with no settings.insights_config " +
		"block has no Query Insights: slow or abusive queries go " +
		"undetected, hiding both performance and security anomalies. " +
		"Enable Query Insights."
}
func (sqlNoQueryInsights) Severity() ir.Severity { return ir.SeverityLow }

func (sqlNoQueryInsights) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlNoQueryInsights) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := sqlSettings(r)
	if !present || !known {
		return nil // settings absent or unresolved: cannot decide
	}
	for _, st := range settings {
		if len(blockList(st, "insights_config")) > 0 {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "settings.insights_config", r.Span,
		"absent", "settings { insights_config { query_insights_enabled = true } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-154: Cloud SQL not highly available
// ---------------------------------------------------------------------------

type sqlNotHighlyAvailable struct{}

func (sqlNotHighlyAvailable) ID() string { return "AEGIS-GCP-154" }
func (sqlNotHighlyAvailable) Title() string {
	return "Cloud SQL instance not highly available"
}
func (sqlNotHighlyAvailable) Description() string {
	return "google_sql_database_instance with settings.availability_type " +
		"other than REGIONAL (the default is ZONAL) has no standby in " +
		"another zone: a zonal outage takes the database offline. Use " +
		"availability_type = \"REGIONAL\" for production."
}
func (sqlNotHighlyAvailable) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlNotHighlyAvailable) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlNotHighlyAvailable) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := sqlSettings(r)
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		at, span, apresent, aknown := blockString(st, "availability_type")
		if apresent && !aknown {
			return nil // unresolved: cannot decide
		}
		if apresent && strings.EqualFold(strings.TrimSpace(at), "REGIONAL") {
			return nil
		}
		actual := "absent (provider default: ZONAL)"
		attrSpan := ir.Span{}
		if apresent {
			actual = at
			attrSpan = span
		}
		return []ir.Finding{mkFinding(s, r, "settings.availability_type",
			evidenceSpan(attrSpan, r.Span), actual,
			"settings { availability_type = \"REGIONAL\" }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-155: Cloud SQL user password stored in configuration
// ---------------------------------------------------------------------------

type sqlUserPasswordInConfig struct{}

func (sqlUserPasswordInConfig) ID() string { return "AEGIS-GCP-155" }
func (sqlUserPasswordInConfig) Title() string {
	return "Cloud SQL user password stored in Terraform configuration"
}
func (sqlUserPasswordInConfig) Description() string {
	return "google_sql_user with a plaintext password in configuration " +
		"persists the credential in Terraform state and plan output. " +
		"Generate passwords outside Terraform (e.g. Secret Manager) and " +
		"reference them, or use IAM database authentication."
}
func (sqlUserPasswordInConfig) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlUserPasswordInConfig) AppliesTo(resType string) bool {
	return resType == "google_sql_user"
}

func (s sqlUserPasswordInConfig) Check(r ir.Resource) []ir.Finding {
	pw, span, present, known := getString(r, "password")
	if !present || !known {
		return nil
	}
	if strings.TrimSpace(pw) == "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "password", span,
		"plaintext password in configuration",
		"password sourced from Secret Manager or IAM authentication")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-156: Cloud SQL backup retention below 7 days
// ---------------------------------------------------------------------------

type sqlLowBackupRetention struct{}

func (sqlLowBackupRetention) ID() string { return "AEGIS-GCP-156" }
func (sqlLowBackupRetention) Title() string {
	return "Cloud SQL backup retention below 7 days"
}
func (sqlLowBackupRetention) Description() string {
	return "google_sql_database_instance with " +
		"settings.backup_configuration.backup_retention_settings." +
		"retained_backups below 7 keeps too little history to recover " +
		"from a slow-burn compromise or logical corruption. Retain at " +
		"least 7 automated backups."
}
func (sqlLowBackupRetention) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlLowBackupRetention) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlLowBackupRetention) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := sqlSettings(r)
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		for _, bc := range sqlBackupConfig(st) {
			for _, br := range blockList(bc, "backup_retention_settings") {
				n, npresent, nknown := blockNum(br, "retained_backups")
				if npresent && !nknown {
					return nil // unresolved: cannot decide
				}
				if npresent && n < 7 {
					return []ir.Finding{mkFinding(s, r,
						"settings.backup_configuration.backup_retention_settings.retained_backups",
						evidenceSpan(ir.Span{}, r.Span),
						strconv.Itoa(int(n)), "retained_backups >= 7")}
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-157: Cloud SQL without password validation policy
// ---------------------------------------------------------------------------

type sqlNoPasswordValidationPolicy struct{}

func (sqlNoPasswordValidationPolicy) ID() string { return "AEGIS-GCP-157" }
func (sqlNoPasswordValidationPolicy) Title() string {
	return "Cloud SQL instance without password validation policy"
}
func (sqlNoPasswordValidationPolicy) Description() string {
	return "google_sql_database_instance with no " +
		"settings.password_validation_policy block accepts weak database " +
		"passwords (short, no complexity requirements). Enforce a " +
		"password validation policy."
}
func (sqlNoPasswordValidationPolicy) Severity() ir.Severity { return ir.SeverityLow }

func (sqlNoPasswordValidationPolicy) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlNoPasswordValidationPolicy) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := sqlSettings(r)
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		if len(blockList(st, "password_validation_policy")) > 0 {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "settings.password_validation_policy",
		r.Span, "absent",
		"settings { password_validation_policy { min_length = 12 ... } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-158: Cloud SQL root password stored in configuration
// ---------------------------------------------------------------------------

type sqlRootPasswordInConfig struct{}

func (sqlRootPasswordInConfig) ID() string { return "AEGIS-GCP-158" }
func (sqlRootPasswordInConfig) Title() string {
	return "Cloud SQL root password stored in Terraform configuration"
}
func (sqlRootPasswordInConfig) Description() string {
	return "google_sql_database_instance with a plaintext root_password " +
		"in configuration persists the most privileged database " +
		"credential in Terraform state and plan output. Set the root " +
		"password out-of-band and never store it in configuration."
}
func (sqlRootPasswordInConfig) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlRootPasswordInConfig) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlRootPasswordInConfig) Check(r ir.Resource) []ir.Finding {
	pw, span, present, known := getString(r, "root_password")
	if !present || !known {
		return nil
	}
	if strings.TrimSpace(pw) == "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "root_password", span,
		"plaintext root password in configuration",
		"set the root password out-of-band, outside Terraform")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-159: Cloud SQL transaction log retention below 7 days
// ---------------------------------------------------------------------------

type sqlShortTransactionLogRetention struct{}

func (sqlShortTransactionLogRetention) ID() string { return "AEGIS-GCP-159" }
func (sqlShortTransactionLogRetention) Title() string {
	return "Cloud SQL transaction log retention below 7 days"
}
func (sqlShortTransactionLogRetention) Description() string {
	return "google_sql_database_instance with " +
		"settings.backup_configuration.transaction_log_retention_days " +
		"below 7 keeps too little transaction history for point-in-time " +
		"recovery after a delayed-detonation incident. Retain at least " +
		"7 days."
}
func (sqlShortTransactionLogRetention) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlShortTransactionLogRetention) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlShortTransactionLogRetention) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := sqlSettings(r)
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		for _, bc := range sqlBackupConfig(st) {
			n, npresent, nknown := blockNum(bc, "transaction_log_retention_days")
			if npresent && !nknown {
				return nil // unresolved: cannot decide
			}
			if npresent && n < 7 {
				return []ir.Finding{mkFinding(s, r,
					"settings.backup_configuration.transaction_log_retention_days",
					evidenceSpan(ir.Span{}, r.Span),
					strconv.Itoa(int(n)), "transaction_log_retention_days >= 7")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-160: Cloud SQL without binary logging
// ---------------------------------------------------------------------------

type sqlNoBinaryLog struct{}

func (sqlNoBinaryLog) ID() string { return "AEGIS-GCP-160" }
func (sqlNoBinaryLog) Title() string {
	return "Cloud SQL MySQL instance without binary logging"
}
func (sqlNoBinaryLog) Description() string {
	return "google_sql_database_instance with a backup_configuration " +
		"block but binary_log_enabled not true keeps no binary logs: " +
		"MySQL point-in-time recovery and change auditing are " +
		"impossible. Enable binary logging."
}
func (sqlNoBinaryLog) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlNoBinaryLog) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlNoBinaryLog) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := sqlSettings(r)
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		bcs := sqlBackupConfig(st)
		if len(bcs) == 0 {
			continue // no backup config: rule 003 territory
		}
		for _, bc := range bcs {
			en, span, epresent, eknown := blockBool(bc, "binary_log_enabled")
			if epresent && !eknown {
				return nil // unresolved: cannot decide
			}
			if epresent && en {
				return nil
			}
			actual := "absent (provider default: false)"
			if epresent {
				actual = "false"
			}
			return []ir.Finding{mkFinding(s, r,
				"settings.backup_configuration.binary_log_enabled",
				evidenceSpan(span, r.Span), actual,
				"binary_log_enabled = true")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-161: Cloud SQL with weak password encryption
// ---------------------------------------------------------------------------

type sqlWeakPasswordEncryption struct{}

func (sqlWeakPasswordEncryption) ID() string { return "AEGIS-GCP-161" }
func (sqlWeakPasswordEncryption) Title() string {
	return "Cloud SQL with MD5 password encryption"
}
func (sqlWeakPasswordEncryption) Description() string {
	return "google_sql_database_instance with settings.database_flags " +
		"password_encryption = \"md5\" stores password hashes with MD5, " +
		"which is fast to brute-force. Use scram-sha-256 (the modern " +
		"default) instead."
}
func (sqlWeakPasswordEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlWeakPasswordEncryption) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlWeakPasswordEncryption) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := sqlSettings(r)
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		for _, f := range blockList(st, "database_flags") {
			name, _, npresent, nknown := blockString(f, "name")
			if !npresent || !nknown {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(name), "password_encryption") {
				continue
			}
			val, span, vpresent, vknown := blockString(f, "value")
			if !vpresent || !vknown {
				return nil // unresolved: cannot decide
			}
			if strings.EqualFold(strings.TrimSpace(val), "md5") {
				return []ir.Finding{mkFinding(s, r,
					"settings.database_flags (password_encryption)", span,
					val, "password_encryption = \"scram-sha-256\"")}
			}
			return nil
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-162: Cloud SQL SSL mode allows unencrypted connections
// ---------------------------------------------------------------------------

type sqlSSLModePermissive struct{}

func (sqlSSLModePermissive) ID() string { return "AEGIS-GCP-162" }
func (sqlSSLModePermissive) Title() string {
	return "Cloud SQL SSL mode permits unencrypted connections"
}
func (sqlSSLModePermissive) Description() string {
	return "google_sql_database_instance with " +
		"settings.ip_configuration.ssl_mode = " +
		"\"ALLOW_UNENCRYPTED_AND_ENCRYPTED\" accepts plaintext database " +
		"connections, exposing credentials and data to network sniffing. " +
		"Use ENCRYPTED_ONLY or TRUSTED_CLIENT_CERTIFICATE_REQUIRED."
}
func (sqlSSLModePermissive) Severity() ir.Severity { return ir.SeverityHigh }

func (sqlSSLModePermissive) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlSSLModePermissive) Check(r ir.Resource) []ir.Finding {
	settings, _, present, known := sqlSettings(r)
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		for _, ipc := range blockList(st, "ip_configuration") {
			mode, span, mpresent, mknown := blockString(ipc, "ssl_mode")
			if !mpresent || !mknown {
				continue // legacy require_ssl is rule 008 territory
			}
			if strings.EqualFold(strings.TrimSpace(mode),
				"ALLOW_UNENCRYPTED_AND_ENCRYPTED") {
				return []ir.Finding{mkFinding(s, r,
					"settings.ip_configuration.ssl_mode", span, mode,
					"ssl_mode = \"ENCRYPTED_ONLY\"")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-163: GKE cluster without security posture management
// ---------------------------------------------------------------------------

type gkeNoSecurityPosture struct{}

func (gkeNoSecurityPosture) ID() string { return "AEGIS-GCP-163" }
func (gkeNoSecurityPosture) Title() string {
	return "GKE cluster without security posture management"
}
func (gkeNoSecurityPosture) Description() string {
	return "google_container_cluster with no security_posture_config " +
		"block (or vulnerability_mode = \"DISABLED\") gets no workload " +
		"vulnerability scanning: known CVEs in running workloads go " +
		"unreported. Enable security posture management."
}
func (gkeNoSecurityPosture) Severity() ir.Severity { return ir.SeverityLow }

func (gkeNoSecurityPosture) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeNoSecurityPosture) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "security_posture_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		for _, b := range blks {
			mode, _, mpresent, mknown := blockString(b, "vulnerability_mode")
			if mpresent && !mknown {
				return nil // unresolved: cannot decide
			}
			if mpresent && !strings.EqualFold(strings.TrimSpace(mode), "DISABLED") {
				return nil // scanning enabled
			}
		}
	}
	actual := "absent"
	if present {
		actual = "vulnerability_mode = \"DISABLED\""
	}
	return []ir.Finding{mkFinding(s, r, "security_posture_config",
		evidenceSpan(span, r.Span), actual,
		"security_posture_config { vulnerability_mode = \"BASIC\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-164: GKE cluster nodes with legacy metadata endpoints
// ---------------------------------------------------------------------------

type gkeLegacyMetadataEndpoints struct{}

func (gkeLegacyMetadataEndpoints) ID() string { return "AEGIS-GCP-164" }
func (gkeLegacyMetadataEndpoints) Title() string {
	return "GKE cluster nodes with legacy metadata endpoints enabled"
}
func (gkeLegacyMetadataEndpoints) Description() string {
	return "google_container_cluster node_config.metadata without " +
		"disable-legacy-endpoints = \"true\" exposes the legacy GCE " +
		"metadata endpoints (v0.1/v1beta1) on nodes, widening SSRF and " +
		"credential-theft impact. Disable legacy endpoints."
}
func (gkeLegacyMetadataEndpoints) Severity() ir.Severity { return ir.SeverityMedium }

func (gkeLegacyMetadataEndpoints) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func legacyMetadataEndpointsFinding(rule ir.Rule, r ir.Resource, resType string) []ir.Finding {
	val, span, present, known := nodeConfigMetaString(r, "disable-legacy-endpoints")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.EqualFold(strings.TrimSpace(val), "true") {
		return nil
	}
	actual := "absent (legacy endpoints enabled)"
	if present {
		actual = val
	}
	return []ir.Finding{mkFinding(rule, r, resType+".node_config.metadata",
		evidenceSpan(span, r.Span), actual,
		"metadata = { disable-legacy-endpoints = \"true\" }")}
}

func (s gkeLegacyMetadataEndpoints) Check(r ir.Resource) []ir.Finding {
	return legacyMetadataEndpointsFinding(s, r, "google_container_cluster")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-165: GKE cluster without etcd secrets encryption
// ---------------------------------------------------------------------------

type gkeNoDatabaseEncryption struct{}

func (gkeNoDatabaseEncryption) ID() string { return "AEGIS-GCP-165" }
func (gkeNoDatabaseEncryption) Title() string {
	return "GKE cluster without application-layer secrets encryption"
}
func (gkeNoDatabaseEncryption) Description() string {
	return "google_container_cluster with no database_encryption block " +
		"stores Kubernetes secrets in etcd encrypted only at the storage " +
		"layer with Google-managed keys. Enable application-layer " +
		"secrets encryption with a customer-managed Cloud KMS key."
}
func (gkeNoDatabaseEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (gkeNoDatabaseEncryption) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeNoDatabaseEncryption) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "database_encryption")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil // configured (any state counts as an explicit choice)
	}
	return []ir.Finding{mkFinding(s, r, "database_encryption",
		evidenceSpan(span, r.Span), "absent",
		"database_encryption { state = \"ENCRYPTED\" key_name = \"<kms-key>\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-166: GKE cluster without Google Groups for RBAC
// ---------------------------------------------------------------------------

type gkeNoAuthenticatorGroups struct{}

func (gkeNoAuthenticatorGroups) ID() string { return "AEGIS-GCP-166" }
func (gkeNoAuthenticatorGroups) Title() string {
	return "GKE cluster without Google Groups for RBAC"
}
func (gkeNoAuthenticatorGroups) Description() string {
	return "google_container_cluster with no authenticator_groups_config " +
		"block cannot bind Kubernetes RBAC to Google Groups: access is " +
		"managed per-user instead of through group membership, which " +
		"drifts during onboarding and offboarding. Configure " +
		"authenticator_groups_config."
}
func (gkeNoAuthenticatorGroups) Severity() ir.Severity { return ir.SeverityLow }

func (gkeNoAuthenticatorGroups) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeNoAuthenticatorGroups) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "authenticator_groups_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "authenticator_groups_config",
		evidenceSpan(span, r.Span), "absent",
		"authenticator_groups_config { security_group = \"gke-security-groups@<domain>\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-167: GKE alpha cluster
// ---------------------------------------------------------------------------

type gkeAlphaCluster struct{}

func (gkeAlphaCluster) ID() string { return "AEGIS-GCP-167" }
func (gkeAlphaCluster) Title() string {
	return "GKE alpha cluster enabled"
}
func (gkeAlphaCluster) Description() string {
	return "google_container_cluster with enable_kubernetes_alpha = true " +
		"runs experimental Kubernetes features with no SLA, no security " +
		"patch guarantees, and automatic deletion after 30 days. Never " +
		"use alpha clusters for production or sensitive workloads."
}
func (gkeAlphaCluster) Severity() ir.Severity { return ir.SeverityHigh }

func (gkeAlphaCluster) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeAlphaCluster) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "enable_kubernetes_alpha")
	if !present || !known {
		return nil // default is disabled
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "enable_kubernetes_alpha", span,
		"true", "enable_kubernetes_alpha = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-168: GKE cluster without VPC-native networking
// ---------------------------------------------------------------------------

type gkeNoVPCNative struct{}

func (gkeNoVPCNative) ID() string { return "AEGIS-GCP-168" }
func (gkeNoVPCNative) Title() string {
	return "GKE cluster without VPC-native networking"
}
func (gkeNoVPCNative) Description() string {
	return "google_container_cluster with no ip_allocation_policy block " +
		"uses routes-based networking, which lacks alias IPs for pods: " +
		"network policies and VPC flow logs cannot distinguish pod " +
		"traffic. Use VPC-native clusters with ip_allocation_policy."
}
func (gkeNoVPCNative) Severity() ir.Severity { return ir.SeverityMedium }

func (gkeNoVPCNative) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeNoVPCNative) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "ip_allocation_policy")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "ip_allocation_policy",
		evidenceSpan(span, r.Span), "absent (routes-based networking)",
		"ip_allocation_policy { cluster_ipv4_cidr_block = \"...\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-169: GKE cluster allows external IPs for services
// ---------------------------------------------------------------------------

type gkeServiceExternalIPs struct{}

func (gkeServiceExternalIPs) ID() string { return "AEGIS-GCP-169" }
func (gkeServiceExternalIPs) Title() string {
	return "GKE cluster allows external IPs for Kubernetes services"
}
func (gkeServiceExternalIPs) Description() string {
	return "google_container_cluster with " +
		"service_external_ips_config.enabled = true lets service owners " +
		"attach arbitrary external IPs to Services, bypassing ingress " +
		"controls and exposing workloads directly. Keep it disabled " +
		"unless external IPs are centrally managed."
}
func (gkeServiceExternalIPs) Severity() ir.Severity { return ir.SeverityMedium }

func (gkeServiceExternalIPs) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeServiceExternalIPs) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "service_external_ips_config")
	if !present || !known {
		return nil // default is disabled
	}
	for _, b := range blks {
		en, _, epresent, eknown := blockBool(b, "enabled")
		if epresent && !eknown {
			return nil // unresolved: cannot decide
		}
		if epresent && en {
			return []ir.Finding{mkFinding(s, r,
				"service_external_ips_config.enabled",
				evidenceSpan(span, r.Span), "true",
				"service_external_ips_config { enabled = false }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-170: GKE master authorized networks open to the world
// ---------------------------------------------------------------------------

type gkeMasterAuthNetworksOpen struct{}

func (gkeMasterAuthNetworksOpen) ID() string { return "AEGIS-GCP-170" }
func (gkeMasterAuthNetworksOpen) Title() string {
	return "GKE master authorized networks include 0.0.0.0/0"
}
func (gkeMasterAuthNetworksOpen) Description() string {
	return "google_container_cluster master_authorized_networks_config " +
		"with a cidr_block of 0.0.0.0/0 authorizes the entire internet " +
		"to reach the Kubernetes API server, defeating the purpose of " +
		"authorized networks. Restrict CIDR blocks to trusted ranges."
}
func (gkeMasterAuthNetworksOpen) Severity() ir.Severity { return ir.SeverityHigh }

func (gkeMasterAuthNetworksOpen) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeMasterAuthNetworksOpen) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "master_authorized_networks_config")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		for _, cb := range blockList(b, "cidr_blocks") {
			cidr, span, cpresent, cknown := blockString(cb, "cidr_block")
			if !cpresent || !cknown {
				continue
			}
			if strings.TrimSpace(cidr) == "0.0.0.0/0" {
				return []ir.Finding{mkFinding(s, r,
					"master_authorized_networks_config.cidr_blocks.cidr_block",
					span, cidr, "cidr_block = \"<trusted-range>\"")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-171: GKE node pool with legacy metadata endpoints
// ---------------------------------------------------------------------------

type gkeNodePoolLegacyMetadata struct{}

func (gkeNodePoolLegacyMetadata) ID() string { return "AEGIS-GCP-171" }
func (gkeNodePoolLegacyMetadata) Title() string {
	return "GKE node pool with legacy metadata endpoints enabled"
}
func (gkeNodePoolLegacyMetadata) Description() string {
	return "google_container_node_pool node_config.metadata without " +
		"disable-legacy-endpoints = \"true\" exposes the legacy GCE " +
		"metadata endpoints (v0.1/v1beta1) on pool nodes, widening SSRF " +
		"and credential-theft impact. Disable legacy endpoints per pool."
}
func (gkeNodePoolLegacyMetadata) Severity() ir.Severity { return ir.SeverityMedium }

func (gkeNodePoolLegacyMetadata) AppliesTo(resType string) bool {
	return resType == "google_container_node_pool"
}

func (s gkeNodePoolLegacyMetadata) Check(r ir.Resource) []ir.Finding {
	return legacyMetadataEndpointsFinding(s, r, "google_container_node_pool")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-172: GKE node boot disks without CMEK
// ---------------------------------------------------------------------------

type gkeNodeBootDiskNoCMEK struct{}

func (gkeNodeBootDiskNoCMEK) ID() string { return "AEGIS-GCP-172" }
func (gkeNodeBootDiskNoCMEK) Title() string {
	return "GKE node boot disks without customer-managed encryption"
}
func (gkeNodeBootDiskNoCMEK) Description() string {
	return "google_container_cluster / google_container_node_pool " +
		"node_config without boot_disk_kms_key encrypts node boot disks " +
		"with Google-managed keys only. Assign a customer-managed Cloud " +
		"KMS key for control over rotation and revocation."
}
func (gkeNodeBootDiskNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (gkeNodeBootDiskNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_container_cluster" ||
		resType == "google_container_node_pool"
}

func (s gkeNodeBootDiskNoCMEK) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "node_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present {
		for _, b := range blks {
			key, _, kpresent, kknown := blockString(b, "boot_disk_kms_key")
			if kpresent && !kknown {
				return nil // unresolved: cannot decide
			}
			if kpresent && strings.TrimSpace(key) != "" {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "node_config.boot_disk_kms_key",
		evidenceSpan(span, r.Span), "absent (Google-managed keys)",
		"node_config { boot_disk_kms_key = \"<kms-key>\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-173: Compute instance without Confidential VM
// ---------------------------------------------------------------------------

type computeNoConfidentialVM struct{}

func (computeNoConfidentialVM) ID() string { return "AEGIS-GCP-173" }
func (computeNoConfidentialVM) Title() string {
	return "Compute instance without Confidential VM"
}
func (computeNoConfidentialVM) Description() string {
	return "google_compute_instance with no confidential_instance_config " +
		"block runs without memory encryption and remote attestation: " +
		"in-use data is visible to the hypervisor layer. Enable " +
		"Confidential VM for sensitive workloads."
}
func (computeNoConfidentialVM) Severity() ir.Severity { return ir.SeverityLow }

func (computeNoConfidentialVM) AppliesTo(resType string) bool {
	return resType == "google_compute_instance"
}

func (s computeNoConfidentialVM) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "confidential_instance_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "confidential_instance_config",
		evidenceSpan(span, r.Span), "absent",
		"confidential_instance_config { enable_confidential_compute = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-174: Compute instance with vTPM disabled
// ---------------------------------------------------------------------------

type computeVTPMOff struct{}

func (computeVTPMOff) ID() string { return "AEGIS-GCP-174" }
func (computeVTPMOff) Title() string {
	return "Compute instance with vTPM disabled"
}
func (computeVTPMOff) Description() string {
	return "google_compute_instance shielded_instance_config with " +
		"enable_vtpm = false disables the virtual TPM: measured boot " +
		"and secrets sealed to platform state stop working. Keep vTPM " +
		"enabled on Shielded VMs."
}
func (computeVTPMOff) Severity() ir.Severity { return ir.SeverityMedium }

func (computeVTPMOff) AppliesTo(resType string) bool {
	return resType == "google_compute_instance"
}

// shieldedFlagOff fires when a shielded_instance_config flag is explicitly
// false. An absent block means provider-secure defaults: no finding.
func shieldedFlagOff(rule ir.Rule, r ir.Resource, flag, attr string) []ir.Finding {
	blks, _, present, known := getBlocks(r, "shielded_instance_config")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		en, span, epresent, eknown := blockBool(b, flag)
		if epresent && !eknown {
			return nil // unresolved: cannot decide
		}
		if epresent && !en {
			return []ir.Finding{mkFinding(rule, r, attr, span,
				"false", attr+" = true")}
		}
	}
	return nil
}

func (s computeVTPMOff) Check(r ir.Resource) []ir.Finding {
	return shieldedFlagOff(s, r, "enable_vtpm", "shielded_instance_config.enable_vtpm")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-175: Compute instance with integrity monitoring disabled
// ---------------------------------------------------------------------------

type computeIntegrityMonOff struct{}

func (computeIntegrityMonOff) ID() string { return "AEGIS-GCP-175" }
func (computeIntegrityMonOff) Title() string {
	return "Compute instance with integrity monitoring disabled"
}
func (computeIntegrityMonOff) Description() string {
	return "google_compute_instance shielded_instance_config with " +
		"enable_integrity_monitoring = false stops boot-integrity " +
		"attestation reporting: rootkits that survive reboot go " +
		"undetected. Keep integrity monitoring enabled on Shielded VMs."
}
func (computeIntegrityMonOff) Severity() ir.Severity { return ir.SeverityLow }

func (computeIntegrityMonOff) AppliesTo(resType string) bool {
	return resType == "google_compute_instance"
}

func (s computeIntegrityMonOff) Check(r ir.Resource) []ir.Finding {
	return shieldedFlagOff(s, r, "enable_integrity_monitoring",
		"shielded_instance_config.enable_integrity_monitoring")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-176: Compute instance without OS Login 2FA
// ---------------------------------------------------------------------------

type computeNoOSLogin2FA struct{}

func (computeNoOSLogin2FA) ID() string { return "AEGIS-GCP-176" }
func (computeNoOSLogin2FA) Title() string {
	return "Compute instance without OS Login two-factor authentication"
}
func (computeNoOSLogin2FA) Description() string {
	return "google_compute_instance metadata with enable-oslogin-2fa " +
		"present but not \"TRUE\" allows OS Login SSH sessions without " +
		"a second factor. Set enable-oslogin-2fa = \"TRUE\" where OS " +
		"Login is used."
}
func (computeNoOSLogin2FA) Severity() ir.Severity { return ir.SeverityLow }

func (computeNoOSLogin2FA) AppliesTo(resType string) bool {
	return resType == "google_compute_instance"
}

func (s computeNoOSLogin2FA) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := topMetaString(r, "enable-oslogin-2fa")
	if !present || !known {
		return nil // absent: project default may apply; cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(val), "TRUE") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "metadata.enable-oslogin-2fa", span,
		val, "metadata = { enable-oslogin-2fa = \"TRUE\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-177: Instance template without secure boot
// ---------------------------------------------------------------------------

type instanceTemplateNoSecureBoot struct{}

func (instanceTemplateNoSecureBoot) ID() string { return "AEGIS-GCP-177" }
func (instanceTemplateNoSecureBoot) Title() string {
	return "Instance template without secure boot"
}
func (instanceTemplateNoSecureBoot) Description() string {
	return "google_compute_instance_template shielded_instance_config " +
		"without enable_secure_boot = true launches instances that skip " +
		"boot integrity verification: every VM stamped from the " +
		"template inherits the gap. Enable secure boot in the template."
}
func (instanceTemplateNoSecureBoot) Severity() ir.Severity { return ir.SeverityMedium }

func (instanceTemplateNoSecureBoot) AppliesTo(resType string) bool {
	return resType == "google_compute_instance_template"
}

func (s instanceTemplateNoSecureBoot) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "shielded_instance_config")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "shielded_instance_config", r.Span,
			"absent", "shielded_instance_config { enable_secure_boot = true }")}
	}
	en, span, epresent, eknown := blockBool(blks[0], "enable_secure_boot")
	if epresent && !eknown {
		return nil
	}
	if epresent && !en {
		return []ir.Finding{mkFinding(s, r,
			"shielded_instance_config.enable_secure_boot", span,
			"false", "enable_secure_boot = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-178: Instance template with public IP
// ---------------------------------------------------------------------------

type instanceTemplatePublicIP struct{}

func (instanceTemplatePublicIP) ID() string { return "AEGIS-GCP-178" }
func (instanceTemplatePublicIP) Title() string {
	return "Instance template with public IP"
}
func (instanceTemplatePublicIP) Description() string {
	return "google_compute_instance_template with an access_config block " +
		"on a network_interface gives every VM stamped from the " +
		"template an ephemeral public IP. Remove access_config for " +
		"internal-only instance templates."
}
func (instanceTemplatePublicIP) Severity() ir.Severity { return ir.SeverityHigh }

func (instanceTemplatePublicIP) AppliesTo(resType string) bool {
	return resType == "google_compute_instance_template"
}

func (s instanceTemplatePublicIP) Check(r ir.Resource) []ir.Finding {
	nics, _, present, known := getBlocks(r, "network_interface")
	if !present || !known {
		return nil
	}
	for _, nic := range nics {
		if len(blockList(nic, "access_config")) > 0 {
			return []ir.Finding{mkFinding(s, r,
				"network_interface.access_config",
				evidenceSpan(ir.Span{}, r.Span),
				"access_config present (ephemeral public IP)",
				"remove access_config for internal-only templates")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-179: Instance template without OS Login
// ---------------------------------------------------------------------------

type instanceTemplateNoOSLogin struct{}

func (instanceTemplateNoOSLogin) ID() string { return "AEGIS-GCP-179" }
func (instanceTemplateNoOSLogin) Title() string {
	return "Instance template without OS Login"
}
func (instanceTemplateNoOSLogin) Description() string {
	return "google_compute_instance_template metadata without " +
		"enable-oslogin = TRUE stamps instances that fall back to " +
		"project-wide SSH keys instead of IAM-managed access. Enable " +
		"OS Login in the template."
}
func (instanceTemplateNoOSLogin) Severity() ir.Severity { return ir.SeverityMedium }

func (instanceTemplateNoOSLogin) AppliesTo(resType string) bool {
	return resType == "google_compute_instance_template"
}

func (s instanceTemplateNoOSLogin) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := topMetaString(r, "enable-oslogin")
	if !present || !known {
		return nil // absent: project default may apply; cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(val), "TRUE") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "metadata.enable-oslogin", span,
		val, "metadata = { enable-oslogin = \"TRUE\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-180: Instance template with serial port access
// ---------------------------------------------------------------------------

type instanceTemplateSerialPort struct{}

func (instanceTemplateSerialPort) ID() string { return "AEGIS-GCP-180" }
func (instanceTemplateSerialPort) Title() string {
	return "Instance template with serial port access enabled"
}
func (instanceTemplateSerialPort) Description() string {
	return "google_compute_instance_template metadata with " +
		"serial-port-enable = TRUE opens the serial console on every VM " +
		"stamped from the template, offering an interactive shell that " +
		"bypasses SSH controls. Keep the serial port disabled."
}
func (instanceTemplateSerialPort) Severity() ir.Severity { return ir.SeverityMedium }

func (instanceTemplateSerialPort) AppliesTo(resType string) bool {
	return resType == "google_compute_instance_template"
}

func (s instanceTemplateSerialPort) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := topMetaString(r, "serial-port-enable")
	if !present || !known {
		return nil // default is disabled
	}
	if strings.EqualFold(strings.TrimSpace(val), "TRUE") {
		return []ir.Finding{mkFinding(s, r, "metadata.serial-port-enable", span,
			val, "remove serial-port-enable (default disabled)")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-181: Compute snapshot without CMEK
// ---------------------------------------------------------------------------

type snapshotNoCMEK struct{}

func (snapshotNoCMEK) ID() string { return "AEGIS-GCP-181" }
func (snapshotNoCMEK) Title() string {
	return "Compute snapshot without customer-managed encryption"
}
func (snapshotNoCMEK) Description() string {
	return "google_compute_snapshot with no snapshot_encryption_key " +
		"block encrypts the snapshot with Google-managed keys only. " +
		"Assign a customer-managed Cloud KMS key so snapshots inherit " +
		"your rotation and revocation controls."
}
func (snapshotNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (snapshotNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_compute_snapshot"
}

func (s snapshotNoCMEK) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "snapshot_encryption_key")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "snapshot_encryption_key",
		evidenceSpan(span, r.Span), "absent (Google-managed keys)",
		"snapshot_encryption_key { kms_key_self_link = \"<kms-key>\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-182: Compute image without CMEK
// ---------------------------------------------------------------------------

type imageNoCMEK struct{}

func (imageNoCMEK) ID() string { return "AEGIS-GCP-182" }
func (imageNoCMEK) Title() string {
	return "Compute image without customer-managed encryption"
}
func (imageNoCMEK) Description() string {
	return "google_compute_image with no image_encryption_key block " +
		"encrypts the image with Google-managed keys only. Assign a " +
		"customer-managed Cloud KMS key so images inherit your " +
		"rotation and revocation controls."
}
func (imageNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (imageNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_compute_image"
}

func (s imageNoCMEK) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "image_encryption_key")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "image_encryption_key",
		evidenceSpan(span, r.Span), "absent (Google-managed keys)",
		"image_encryption_key { kms_key_self_link = \"<kms-key>\" }")}
}
