// Package aws implements the Aegis AWS security rule pack.
//
// Deep database rules (AEGIS-AWS-700–719): second-pass checks for RDS,
// Aurora, Redshift, ElastiCache, and Neptune covering snapshot hygiene,
// backup posture, parameter-group security, and deletion safety. Unknown
// values never fire; absent attributes are evaluated against the provider's
// insecure default.
package aws

import (
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// DatabasesDeepRules returns the deep-database rules in ID order (700-719).
func DatabasesDeepRules() []ir.Rule {
	return []ir.Rule{
		auroraPerfInsightsNoCMK{},      // AEGIS-AWS-700
		dbInstanceNoEnhancedMon{},      // AEGIS-AWS-701
		dbInstanceNoCopyTagsSnapshot{}, // AEGIS-AWS-702
		auroraSkipFinalSnapshot{},      // AEGIS-AWS-703
		auroraNoAutomatedBackup{},      // AEGIS-AWS-704
		dbClusterSnapshotShared{},     // AEGIS-AWS-705
		dbInstanceDefaultOptionGroup{}, // AEGIS-AWS-706
		dbSubnetGroupSingleSubnet{},   // AEGIS-AWS-707
		auroraDefaultParamGroup{},     // AEGIS-AWS-708
		dbParamGroupNoForceSSL{},      // AEGIS-AWS-709
		dbInstancePasswordNoRotation{}, // AEGIS-AWS-710
		redshiftNoVersionUpgrade{},    // AEGIS-AWS-711
		redshiftShortSnapshotRet{},    // AEGIS-AWS-712
		redshiftNoCopyTagsSnapshot{},  // AEGIS-AWS-713
		elasticacheNoSnapRetention{},  // AEGIS-AWS-714
		elasticacheNoAtRestEncryption{}, // AEGIS-AWS-715
		elasticacheNoAutoFailover{},   // AEGIS-AWS-716
		elasticacheRGNoSnapRetention{}, // AEGIS-AWS-717
		dbInstanceNoPerfInsights{},    // AEGIS-AWS-718
		neptuneNoDeletionProtection{}, // AEGIS-AWS-719
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-700: Aurora Performance Insights without CMK (medium)
// ---------------------------------------------------------------------------
// Replaces the originally-planned db_instance check: AEGIS-AWS-566
// (rdsPerfInsightsNoCMK) already covers aws_db_instance. This closes the
// gap for aws_rds_cluster, which supports the same attributes.

type auroraPerfInsightsNoCMK struct{}

func (auroraPerfInsightsNoCMK) ID() string { return "AEGIS-AWS-700" }
func (auroraPerfInsightsNoCMK) Title() string {
	return "Aurora Performance Insights without customer-managed KMS key"
}
func (auroraPerfInsightsNoCMK) Description() string {
	return "With performance_insights_enabled, Aurora encrypts its " +
		"telemetry with the AWS-managed key unless " +
		"performance_insights_kms_key_id is set. Use a customer-managed " +
		"key for key-policy control and audit."
}
func (auroraPerfInsightsNoCMK) Severity() ir.Severity { return ir.SeverityMedium }
func (auroraPerfInsightsNoCMK) AppliesTo(resType string) bool {
	return resType == "aws_rds_cluster"
}
func (auroraPerfInsightsNoCMK) Check(r ir.Resource) []ir.Finding {
	enabled, _, epresent, eknown := getBool(r, "performance_insights_enabled")
	if !epresent || !eknown || !enabled {
		return nil
	}
	_, _, kpresent, kknown := getString(r, "performance_insights_kms_key_id")
	if kpresent && !kknown {
		return nil // unresolved: cannot decide
	}
	if kpresent {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-700",
		Title:       (auroraPerfInsightsNoCMK{}).Title(),
		Description: (auroraPerfInsightsNoCMK{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "performance_insights_kms_key_id",
			Span:      r.Span,
			Actual:    "absent (AWS-managed key)",
			Expected:  "performance_insights_kms_key_id set",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-701: RDS instance without enhanced monitoring (low)
// ---------------------------------------------------------------------------
// AEGIS-AWS-636 covers aws_rds_cluster; this is the aws_db_instance
// counterpart.

type dbInstanceNoEnhancedMon struct{}

func (dbInstanceNoEnhancedMon) ID() string { return "AEGIS-AWS-701" }
func (dbInstanceNoEnhancedMon) Title() string {
	return "RDS instance without enhanced monitoring"
}
func (dbInstanceNoEnhancedMon) Description() string {
	return "monitoring_interval is absent or 0, so enhanced monitoring is " +
		"disabled: OS-level metrics that catch host problems are missing. " +
		"Set monitoring_interval between 1 and 60 seconds."
}
func (dbInstanceNoEnhancedMon) Severity() ir.Severity { return ir.SeverityLow }
func (dbInstanceNoEnhancedMon) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (dbInstanceNoEnhancedMon) Check(r ir.Resource) []ir.Finding {
	mi, span, present, known := getNumber(r, "monitoring_interval")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && mi > 0 {
		return nil
	}
	actual := "absent (provider default: 0, disabled)"
	if present {
		actual = "0 (disabled)"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-701",
		Title:       (dbInstanceNoEnhancedMon{}).Title(),
		Description: (dbInstanceNoEnhancedMon{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "monitoring_interval",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "monitoring_interval between 1 and 60",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-702: RDS instance snapshot without tag copying (low)
// ---------------------------------------------------------------------------

type dbInstanceNoCopyTagsSnapshot struct{}

func (dbInstanceNoCopyTagsSnapshot) ID() string { return "AEGIS-AWS-702" }
func (dbInstanceNoCopyTagsSnapshot) Title() string {
	return "RDS instance snapshots do not copy tags"
}
func (dbInstanceNoCopyTagsSnapshot) Description() string {
	return "copy_tags_to_snapshot is absent or false, so automated snapshots " +
		"lose the instance's tags (owner, environment, cost center), which " +
		"breaks tag-based access control and cost allocation on restores."
}
func (dbInstanceNoCopyTagsSnapshot) Severity() ir.Severity { return ir.SeverityLow }
func (dbInstanceNoCopyTagsSnapshot) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (dbInstanceNoCopyTagsSnapshot) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "copy_tags_to_snapshot")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	actual := "absent (provider default: false)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-702",
		Title:       (dbInstanceNoCopyTagsSnapshot{}).Title(),
		Description: (dbInstanceNoCopyTagsSnapshot{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "copy_tags_to_snapshot",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "copy_tags_to_snapshot = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-703: Aurora cluster skips final snapshot (high)
// ---------------------------------------------------------------------------
// Replaces the originally-planned deletion_protection check: AEGIS-AWS-337
// (auroraNoDelProtection) already covers deletion_protection on
// aws_rds_cluster. Final-snapshot skipping is the remaining deletion-safety
// gap in this area.

type auroraSkipFinalSnapshot struct{}

func (auroraSkipFinalSnapshot) ID() string { return "AEGIS-AWS-703" }
func (auroraSkipFinalSnapshot) Title() string {
	return "Aurora cluster skips final snapshot on deletion"
}
func (auroraSkipFinalSnapshot) Description() string {
	return "skip_final_snapshot = true means deleting the cluster destroys " +
		"all data with no final snapshot to restore from. Keep it false " +
		"(with a final_snapshot_identifier) so deletion is recoverable."
}
func (auroraSkipFinalSnapshot) Severity() ir.Severity { return ir.SeverityHigh }
func (auroraSkipFinalSnapshot) AppliesTo(resType string) bool {
	return resType == "aws_rds_cluster"
}
func (auroraSkipFinalSnapshot) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "skip_final_snapshot")
	if !present || !known || !val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-703",
		Title:       (auroraSkipFinalSnapshot{}).Title(),
		Description: (auroraSkipFinalSnapshot{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "skip_final_snapshot",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (with final_snapshot_identifier)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-704: Aurora cluster without automated backups (medium)
// ---------------------------------------------------------------------------
// Replaces the originally-planned backtrack_window check: AEGIS-AWS-632
// (auroraNoBacktracking) already covers it. Automated-backup retention is
// the remaining backup-posture gap for aws_rds_cluster.

type auroraNoAutomatedBackup struct{}

func (auroraNoAutomatedBackup) ID() string { return "AEGIS-AWS-704" }
func (auroraNoAutomatedBackup) Title() string {
	return "Aurora cluster without automated backups"
}
func (auroraNoAutomatedBackup) Description() string {
	return "backup_retention_period is absent or 0, so no automated backups " +
		"are kept and point-in-time recovery is impossible. Retain at " +
		"least 7 days for production clusters."
}
func (auroraNoAutomatedBackup) Severity() ir.Severity { return ir.SeverityMedium }
func (auroraNoAutomatedBackup) AppliesTo(resType string) bool {
	return resType == "aws_rds_cluster"
}
func (auroraNoAutomatedBackup) Check(r ir.Resource) []ir.Finding {
	n, span, present, known := getNumber(r, "backup_retention_period")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && n > 0 {
		return nil
	}
	actual := "absent (provider default: no backups)"
	if present {
		actual = "0"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-704",
		Title:       (auroraNoAutomatedBackup{}).Title(),
		Description: (auroraNoAutomatedBackup{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "backup_retention_period",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "backup_retention_period >= 7",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-705: Aurora cluster snapshot shared with other accounts (high)
// ---------------------------------------------------------------------------
// Replaces the originally-planned copy_tags_to_snapshot check: AEGIS-AWS-633
// (auroraNoCopyTagsSnapshot) already covers it. Snapshot sharing is the
// remaining snapshot-hygiene gap in this area.

type dbClusterSnapshotShared struct{}

func (dbClusterSnapshotShared) ID() string { return "AEGIS-AWS-705" }
func (dbClusterSnapshotShared) Title() string {
	return "Aurora cluster snapshot shared with other accounts"
}
func (dbClusterSnapshotShared) Description() string {
	return "shared_accounts is non-empty, so the cluster snapshot (with " +
		"its data) is accessible to other AWS accounts. Sharing snapshots " +
		"leaks production data outside the account boundary; unshare it " +
		"unless the recipient is verified."
}
func (dbClusterSnapshotShared) Severity() ir.Severity { return ir.SeverityHigh }
func (dbClusterSnapshotShared) AppliesTo(resType string) bool {
	return resType == "aws_db_cluster_snapshot"
}
func (dbClusterSnapshotShared) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["shared_accounts"]
	if !ok {
		return nil
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	l, ok := v.AsList()
	if !ok || len(l) == 0 {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-705",
		Title:       (dbClusterSnapshotShared{}).Title(),
		Description: (dbClusterSnapshotShared{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "shared_accounts",
			Span:      evidenceSpan(v.Span, r.Span),
			Actual:    fmt.Sprintf("%d account(s) listed", len(l)),
			Expected:  "shared_accounts empty (not shared)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-706: RDS instance on the default option group (low)
// ---------------------------------------------------------------------------

type dbInstanceDefaultOptionGroup struct{}

func (dbInstanceDefaultOptionGroup) ID() string { return "AEGIS-AWS-706" }
func (dbInstanceDefaultOptionGroup) Title() string {
	return "RDS instance on the default option group"
}
func (dbInstanceDefaultOptionGroup) Description() string {
	return "option_group_name is absent or a default group, so the " +
		"instance runs with AWS's generic options (e.g. no OEM, no " +
		"MariaDB audit plugin). Use a purpose-built option group."
}
func (dbInstanceDefaultOptionGroup) Severity() ir.Severity { return ir.SeverityLow }
func (dbInstanceDefaultOptionGroup) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (dbInstanceDefaultOptionGroup) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "option_group_name")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && !strings.Contains(strings.ToLower(strings.TrimSpace(val)), "default") {
		return nil
	}
	if !present {
		return absentInsecureDefault(dbInstanceDefaultOptionGroup{}, r,
			"option_group_name",
			"absent (provider default: default option group)",
			"option_group_name = <custom group>")
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-706",
		Title:       (dbInstanceDefaultOptionGroup{}).Title(),
		Description: (dbInstanceDefaultOptionGroup{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "option_group_name",
			Span:      evidenceSpan(span, r.Span),
			Actual:    val,
			Expected:  "option_group_name = <custom group>",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-707: RDS subnet group with a single subnet (medium)
// ---------------------------------------------------------------------------

type dbSubnetGroupSingleSubnet struct{}

func (dbSubnetGroupSingleSubnet) ID() string { return "AEGIS-AWS-707" }
func (dbSubnetGroupSingleSubnet) Title() string {
	return "RDS subnet group with a single subnet"
}
func (dbSubnetGroupSingleSubnet) Description() string {
	return "The DB subnet group spans fewer than 2 subnets, so the " +
		"database cannot be placed multi-AZ: one AZ failure takes it " +
		"down. Cover at least two availability zones."
}
func (dbSubnetGroupSingleSubnet) Severity() ir.Severity { return ir.SeverityMedium }
func (dbSubnetGroupSingleSubnet) AppliesTo(resType string) bool {
	return resType == "aws_db_subnet_group"
}
func (dbSubnetGroupSingleSubnet) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["subnet_ids"]
	if !ok {
		return nil
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	l, ok := v.AsList()
	if !ok {
		return nil // not a list shape: never fire
	}
	if len(l) >= 2 {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-707",
		Title:       (dbSubnetGroupSingleSubnet{}).Title(),
		Description: (dbSubnetGroupSingleSubnet{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "subnet_ids",
			Span:      evidenceSpan(v.Span, r.Span),
			Actual:    fmt.Sprintf("%d subnet(s)", len(l)),
			Expected:  "at least 2 subnets (multi-AZ)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-708: Aurora cluster on the default parameter group (low)
// ---------------------------------------------------------------------------

type auroraDefaultParamGroup struct{}

func (auroraDefaultParamGroup) ID() string { return "AEGIS-AWS-708" }
func (auroraDefaultParamGroup) Title() string {
	return "Aurora cluster on the default parameter group"
}
func (auroraDefaultParamGroup) Description() string {
	return "db_cluster_parameter_group_name is absent or a default group, " +
		"so cluster parameters (TLS enforcement, audit logging) stay at " +
		"AWS defaults. Use a custom parameter group with hardened values."
}
func (auroraDefaultParamGroup) Severity() ir.Severity { return ir.SeverityLow }
func (auroraDefaultParamGroup) AppliesTo(resType string) bool {
	return resType == "aws_rds_cluster"
}
func (auroraDefaultParamGroup) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "db_cluster_parameter_group_name")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(val)), "default") {
		return nil
	}
	if !present {
		return absentInsecureDefault(auroraDefaultParamGroup{}, r,
			"db_cluster_parameter_group_name",
			"absent (provider default: default parameter group)",
			"db_cluster_parameter_group_name = <custom group>")
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-708",
		Title:       (auroraDefaultParamGroup{}).Title(),
		Description: (auroraDefaultParamGroup{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "db_cluster_parameter_group_name",
			Span:      evidenceSpan(span, r.Span),
			Actual:    val,
			Expected:  "db_cluster_parameter_group_name = <custom group>",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-709: RDS parameter group without forced SSL (high)
// ---------------------------------------------------------------------------

type dbParamGroupNoForceSSL struct{}

func (dbParamGroupNoForceSSL) ID() string { return "AEGIS-AWS-709" }
func (dbParamGroupNoForceSSL) Title() string {
	return "RDS parameter group without forced SSL"
}
func (dbParamGroupNoForceSSL) Description() string {
	return "A parameter block sets rds.force_ssl = 0, so clients may " +
		"connect to databases using this group over plaintext, exposing " +
		"queries and credentials on the wire. Set rds.force_ssl = 1."
}
func (dbParamGroupNoForceSSL) Severity() ir.Severity { return ir.SeverityHigh }
func (dbParamGroupNoForceSSL) AppliesTo(resType string) bool {
	return resType == "aws_db_parameter_group"
}
func (dbParamGroupNoForceSSL) Check(r ir.Resource) []ir.Finding {
	params, _, present, known := getBlocks(r, "parameter")
	if !present || !known || len(params) == 0 {
		return nil
	}
	for _, p := range params {
		name, nspan, npresent, nknown := blockString(p, "name")
		if !npresent || !nknown {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(name), "rds.force_ssl") {
			continue
		}
		val, _, vpresent, vknown := blockString(p, "value")
		if !vpresent {
			continue // name set without value: not the disabled case
		}
		if !vknown {
			return nil // unresolved: cannot decide
		}
		if strings.TrimSpace(val) == "0" {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-709",
				Title:       (dbParamGroupNoForceSSL{}).Title(),
				Description: (dbParamGroupNoForceSSL{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "parameter.rds.force_ssl",
					Span:      evidenceSpan(nspan, r.Span),
					Actual:    val,
					Expected:  "rds.force_ssl = 1",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-710: RDS master password without Secrets Manager rotation (medium)
// ---------------------------------------------------------------------------
// Replaces the originally-planned iam_database_authentication check:
// AEGIS-AWS-311 (rdsNoIAMAuth) and AEGIS-AWS-540 (rdsNoIAMAuthScoped)
// already cover it on aws_db_instance. Static master passwords are the
// remaining credential-hygiene gap in this area.

type dbInstancePasswordNoRotation struct{}

func (dbInstancePasswordNoRotation) ID() string { return "AEGIS-AWS-710" }
func (dbInstancePasswordNoRotation) Title() string {
	return "RDS master password not managed by Secrets Manager"
}
func (dbInstancePasswordNoRotation) Description() string {
	return "A plaintext master password is set without " +
		"manage_master_user_password, so the credential sits in state and " +
		"is never rotated automatically. Use manage_master_user_password " +
		"= true so RDS manages rotation in Secrets Manager. The password " +
		"value is never included in findings."
}
func (dbInstancePasswordNoRotation) Severity() ir.Severity { return ir.SeverityMedium }
func (dbInstancePasswordNoRotation) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (dbInstancePasswordNoRotation) Check(r ir.Resource) []ir.Finding {
	pw, pwSpan, pwPresent, pwKnown := getString(r, "password")
	if !pwPresent || !pwKnown || strings.TrimSpace(pw) == "" {
		return nil
	}
	managed, _, mpresent, mknown := getBool(r, "manage_master_user_password")
	if mpresent && !mknown {
		return nil // unresolved: cannot decide
	}
	if mpresent && managed {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-710",
		Title:       (dbInstancePasswordNoRotation{}).Title(),
		Description: (dbInstancePasswordNoRotation{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "password",
			Span:      evidenceSpan(pwSpan, r.Span),
			Actual:    "[REDACTED] (plaintext password in config, no rotation)",
			Expected:  "manage_master_user_password = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-711: Redshift cluster without version upgrades (low)
// ---------------------------------------------------------------------------

type redshiftNoVersionUpgrade struct{}

func (redshiftNoVersionUpgrade) ID() string { return "AEGIS-AWS-711" }
func (redshiftNoVersionUpgrade) Title() string {
	return "Redshift cluster without automatic version upgrades"
}
func (redshiftNoVersionUpgrade) Description() string {
	return "allow_version_upgrade = false opts the cluster out of " +
		"automatic engine upgrades, so security patches arrive late or " +
		"never. Keep it true unless upgrades are pinned deliberately."
}
func (redshiftNoVersionUpgrade) Severity() ir.Severity { return ir.SeverityLow }
func (redshiftNoVersionUpgrade) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}
func (redshiftNoVersionUpgrade) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "allow_version_upgrade")
	if !present || !known || val {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-711",
		Title:       (redshiftNoVersionUpgrade{}).Title(),
		Description: (redshiftNoVersionUpgrade{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "allow_version_upgrade",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "allow_version_upgrade = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-712: Redshift short automated snapshot retention (medium)
// ---------------------------------------------------------------------------

type redshiftShortSnapshotRet struct{}

func (redshiftShortSnapshotRet) ID() string { return "AEGIS-AWS-712" }
func (redshiftShortSnapshotRet) Title() string {
	return "Redshift cluster with short snapshot retention"
}
func (redshiftShortSnapshotRet) Description() string {
	return "automated_snapshot_retention_period is below 7 days, shrinking " +
		"the recovery window after corruption, ransomware, or accidental " +
		"drops. Retain at least 7 days for production clusters."
}
func (redshiftShortSnapshotRet) Severity() ir.Severity { return ir.SeverityMedium }
func (redshiftShortSnapshotRet) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}
func (redshiftShortSnapshotRet) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNumber(r, "automated_snapshot_retention_period")
	if !present || !known {
		return nil
	}
	if days >= 7 {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-712",
		Title:       (redshiftShortSnapshotRet{}).Title(),
		Description: (redshiftShortSnapshotRet{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "automated_snapshot_retention_period",
			Span:      evidenceSpan(span, r.Span),
			Actual:    fmt.Sprintf("%d day(s)", int(days)),
			Expected:  ">= 7 days",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-713: Redshift cluster snapshots without tag copying (low)
// ---------------------------------------------------------------------------

type redshiftNoCopyTagsSnapshot struct{}

func (redshiftNoCopyTagsSnapshot) ID() string { return "AEGIS-AWS-713" }
func (redshiftNoCopyTagsSnapshot) Title() string {
	return "Redshift cluster snapshots do not copy tags"
}
func (redshiftNoCopyTagsSnapshot) Description() string {
	return "copy_tags_to_snapshot is absent or false, so automated " +
		"snapshots lose the cluster's tags, breaking tag-based access " +
		"control and cost allocation on restores."
}
func (redshiftNoCopyTagsSnapshot) Severity() ir.Severity { return ir.SeverityLow }
func (redshiftNoCopyTagsSnapshot) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}
func (redshiftNoCopyTagsSnapshot) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "copy_tags_to_snapshot")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	actual := "absent (provider default: false)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-713",
		Title:       (redshiftNoCopyTagsSnapshot{}).Title(),
		Description: (redshiftNoCopyTagsSnapshot{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "copy_tags_to_snapshot",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "copy_tags_to_snapshot = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-714: ElastiCache cluster without snapshot retention (medium)
// ---------------------------------------------------------------------------

type elasticacheNoSnapRetention struct{}

func (elasticacheNoSnapRetention) ID() string { return "AEGIS-AWS-714" }
func (elasticacheNoSnapRetention) Title() string {
	return "ElastiCache cluster without snapshot retention"
}
func (elasticacheNoSnapRetention) Description() string {
	return "snapshot_retention_limit is absent or 0, so no automated " +
		"snapshots are kept and the cache cannot be restored after " +
		"corruption or accidental flush. Retain snapshots for " +
		"production workloads."
}
func (elasticacheNoSnapRetention) Severity() ir.Severity { return ir.SeverityMedium }
func (elasticacheNoSnapRetention) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_cluster"
}
func (elasticacheNoSnapRetention) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNumber(r, "snapshot_retention_limit")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && days > 0 {
		return nil
	}
	actual := "absent (provider default: no snapshots)"
	if present {
		actual = "0"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-714",
		Title:       (elasticacheNoSnapRetention{}).Title(),
		Description: (elasticacheNoSnapRetention{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "snapshot_retention_limit",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "snapshot_retention_limit > 0",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-715: ElastiCache replication group without at-rest encryption (high)
// ---------------------------------------------------------------------------

type elasticacheNoAtRestEncryption struct{}

func (elasticacheNoAtRestEncryption) ID() string { return "AEGIS-AWS-715" }
func (elasticacheNoAtRestEncryption) Title() string {
	return "ElastiCache replication group without at-rest encryption"
}
func (elasticacheNoAtRestEncryption) Description() string {
	return "at_rest_encryption_enabled is absent or false, so cached data " +
		"(often including sessions and tokens) sits unencrypted on disk. " +
		"Set at_rest_encryption_enabled = true."
}
func (elasticacheNoAtRestEncryption) Severity() ir.Severity { return ir.SeverityHigh }
func (elasticacheNoAtRestEncryption) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}
func (elasticacheNoAtRestEncryption) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "at_rest_encryption_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	if !present {
		return absentInsecureDefault(elasticacheNoAtRestEncryption{}, r,
			"at_rest_encryption_enabled",
			"absent (provider default: false)",
			"at_rest_encryption_enabled = true")
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-715",
		Title:       (elasticacheNoAtRestEncryption{}).Title(),
		Description: (elasticacheNoAtRestEncryption{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "at_rest_encryption_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "at_rest_encryption_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-716: ElastiCache replication group without automatic failover (medium)
// ---------------------------------------------------------------------------

type elasticacheNoAutoFailover struct{}

func (elasticacheNoAutoFailover) ID() string { return "AEGIS-AWS-716" }
func (elasticacheNoAutoFailover) Title() string {
	return "ElastiCache replication group without automatic failover"
}
func (elasticacheNoAutoFailover) Description() string {
	return "automatic_failover_enabled is absent or false, so a primary " +
		"failure leaves the group degraded until someone promotes a " +
		"replica manually. Enable automatic failover for Redis HA."
}
func (elasticacheNoAutoFailover) Severity() ir.Severity { return ir.SeverityMedium }
func (elasticacheNoAutoFailover) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}
func (elasticacheNoAutoFailover) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "automatic_failover_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	// Automatic failover requires replicas; a single-node cluster
	// (num_cache_clusters <= 1) has nothing to fail over to.
	if n, _, np, nk := getNumber(r, "num_cache_clusters"); np && nk && n <= 1 {
		return nil
	}
	actual := "absent (provider default: false)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-716",
		Title:       (elasticacheNoAutoFailover{}).Title(),
		Description: (elasticacheNoAutoFailover{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "automatic_failover_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "automatic_failover_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-717: ElastiCache replication group without snapshot retention (medium)
// ---------------------------------------------------------------------------

type elasticacheRGNoSnapRetention struct{}

func (elasticacheRGNoSnapRetention) ID() string { return "AEGIS-AWS-717" }
func (elasticacheRGNoSnapRetention) Title() string {
	return "ElastiCache replication group without snapshot retention"
}
func (elasticacheRGNoSnapRetention) Description() string {
	return "snapshot_retention_limit is absent or 0 on the replication " +
		"group, so no automated snapshots are kept and the dataset cannot " +
		"be restored after corruption or accidental flush."
}
func (elasticacheRGNoSnapRetention) Severity() ir.Severity { return ir.SeverityMedium }
func (elasticacheRGNoSnapRetention) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}
func (elasticacheRGNoSnapRetention) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNumber(r, "snapshot_retention_limit")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && days > 0 {
		return nil
	}
	actual := "absent (provider default: no snapshots)"
	if present {
		actual = "0"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-717",
		Title:       (elasticacheRGNoSnapRetention{}).Title(),
		Description: (elasticacheRGNoSnapRetention{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "snapshot_retention_limit",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "snapshot_retention_limit > 0",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-718: RDS instance without Performance Insights (low)
// ---------------------------------------------------------------------------

type dbInstanceNoPerfInsights struct{}

func (dbInstanceNoPerfInsights) ID() string { return "AEGIS-AWS-718" }
func (dbInstanceNoPerfInsights) Title() string {
	return "RDS instance without Performance Insights"
}
func (dbInstanceNoPerfInsights) Description() string {
	return "performance_insights_enabled is absent or false, so query-level " +
		"telemetry is unavailable when investigating slow queries or " +
		"suspicious database activity. Enable it for production instances."
}
func (dbInstanceNoPerfInsights) Severity() ir.Severity { return ir.SeverityLow }
func (dbInstanceNoPerfInsights) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (dbInstanceNoPerfInsights) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "performance_insights_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	if !present {
		return absentInsecureDefault(dbInstanceNoPerfInsights{}, r,
			"performance_insights_enabled",
			"absent (provider default: false)",
			"performance_insights_enabled = true")
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-718",
		Title:       (dbInstanceNoPerfInsights{}).Title(),
		Description: (dbInstanceNoPerfInsights{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "performance_insights_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "performance_insights_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-719: Neptune cluster without deletion protection (high)
// ---------------------------------------------------------------------------

type neptuneNoDeletionProtection struct{}

func (neptuneNoDeletionProtection) ID() string { return "AEGIS-AWS-719" }
func (neptuneNoDeletionProtection) Title() string {
	return "Neptune cluster without deletion protection"
}
func (neptuneNoDeletionProtection) Description() string {
	return "deletion_protection is absent or false, so the graph database " +
		"can be deleted by an accidental or malicious API call with no " +
		"guardrail. Set deletion_protection = true on production clusters."
}
func (neptuneNoDeletionProtection) Severity() ir.Severity { return ir.SeverityHigh }
func (neptuneNoDeletionProtection) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}
func (neptuneNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "deletion_protection")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	if !present {
		return absentInsecureDefault(neptuneNoDeletionProtection{}, r,
			"deletion_protection",
			"absent (provider default: false)",
			"deletion_protection = true")
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-719",
		Title:       (neptuneNoDeletionProtection{}).Title(),
		Description: (neptuneNoDeletionProtection{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "deletion_protection",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false",
			Expected:  "deletion_protection = true",
		},
	}}
}
