package gcp

import (
	"testing"

	"aegis/internal/ir"
)

// metaMap builds a metadata map attribute value for tests.
func metaMap(line int, pairs ...any) ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = ks(pairs[i+1].(string), line)
	}
	return ir.Value{Raw: m, Known: true, Span: spanAt(line)}
}

// GCP6Rules must return rules 143..182 in ID order.
func TestGCP6RulesInIDOrder(t *testing.T) {
	rules := GCP6Rules()
	if len(rules) != 40 {
		t.Fatalf("expected 40 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := "AEGIS-GCP-" + itoa(143+i)
		if r.ID() != want {
			t.Fatalf("rule %d: want %s, got %s", i, want, r.ID())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %s missing title/description", want)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-143..152: IAM
// ---------------------------------------------------------------------------

func TestGCP6IAM(t *testing.T) {
	// 143: key past validity
	mustFinding(t, runRule(saKeyExpired{}, res("google_service_account_key", "k",
		map[string]ir.Value{"valid_before": ks("2020-01-01T00:00:00Z", 3)})), "AEGIS-GCP-143")
	mustQuiet(t, runRule(saKeyExpired{}, res("google_service_account_key", "k",
		map[string]ir.Value{"valid_before": ks("2999-01-01T00:00:00Z", 3)})))
	mustQuiet(t, runRule(saKeyExpired{}, res("google_service_account_key", "k",
		map[string]ir.Value{"valid_before": ku(3)})))
	mustQuiet(t, runRule(saKeyExpired{}, res("google_service_account_key", "k", nil)))
	mustQuiet(t, runRule(saKeyExpired{}, res("google_service_account_key", "k",
		map[string]ir.Value{"valid_before": ks("not-a-date", 3)})))

	// 144: untracked service account
	mustFinding(t, runRule(saUntracked{}, res("google_service_account", "s", nil)), "AEGIS-GCP-144")
	mustQuiet(t, runRule(saUntracked{}, res("google_service_account", "s",
		map[string]ir.Value{"display_name": ks("ci deployer", 3)})))
	mustQuiet(t, runRule(saUntracked{}, res("google_service_account", "s",
		map[string]ir.Value{"description": ks("used by ci", 3)})))
	mustQuiet(t, runRule(saUntracked{}, res("google_service_account", "s",
		map[string]ir.Value{"display_name": ku(3)})))

	// 145: weak key algorithm
	f := mustFinding(t, runRule(saKeyWeakAlgorithm{}, res("google_service_account_key", "k",
		map[string]ir.Value{"key_algorithm": ks("KEY_ALG_RSA_1024", 3)})), "AEGIS-GCP-145")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("145: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(saKeyWeakAlgorithm{}, res("google_service_account_key", "k",
		map[string]ir.Value{"key_algorithm": ks("KEY_ALG_RSA_2048", 3)})))
	mustQuiet(t, runRule(saKeyWeakAlgorithm{}, res("google_service_account_key", "k", nil)))
	mustQuiet(t, runRule(saKeyWeakAlgorithm{}, res("google_service_account_key", "k",
		map[string]ir.Value{"key_algorithm": ku(3)})))

	// 146: broad impersonation grant
	mustFinding(t, runRule(saImpersonationBroadGrant{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{
			"role":    ks("roles/iam.serviceAccountTokenCreator", 3),
			"members": strList(4, "group:eng@example.com"),
		})), "AEGIS-GCP-146")
	mustFinding(t, runRule(saImpersonationBroadGrant{}, res("google_project_iam_member", "m",
		map[string]ir.Value{
			"role":   ks("roles/iam.serviceAccountTokenCreator", 3),
			"member": ks("domain:example.com", 4),
		})), "AEGIS-GCP-146")
	mustQuiet(t, runRule(saImpersonationBroadGrant{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{
			"role":    ks("roles/iam.serviceAccountTokenCreator", 3),
			"members": strList(4, "serviceAccount:ci@proj.iam.gserviceaccount.com"),
		})))
	mustQuiet(t, runRule(saImpersonationBroadGrant{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{
			"role":    ks("roles/viewer", 3),
			"members": strList(4, "group:eng@example.com"),
		})))
	mustQuiet(t, runRule(saImpersonationBroadGrant{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{
			"role":    ks("roles/iam.serviceAccountTokenCreator", 3),
			"members": ku(4),
		})))

	// 147: authoritative project IAM policy
	mustFinding(t, runRule(projectIamAuthoritativePolicy{},
		res("google_project_iam_policy", "p", nil)), "AEGIS-GCP-147")
	mustQuiet(t, runRule(projectIamAuthoritativePolicy{},
		res("google_project_iam_binding", "b", nil)))

	// 148: org basic roles
	f = mustFinding(t, runRule(orgIamBasicRoles{}, res("google_organization_iam_binding", "o",
		map[string]ir.Value{
			"role":    ks("roles/owner", 3),
			"members": strList(4, "user:a@example.com"),
		})), "AEGIS-GCP-148")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("148: wrong severity %s", f.Severity)
	}
	mustFinding(t, runRule(orgIamBasicRoles{}, res("google_organization_iam_member", "o",
		map[string]ir.Value{
			"role":   ks("roles/editor", 3),
			"member": ks("group:e@example.com", 4),
		})), "AEGIS-GCP-148")
	mustQuiet(t, runRule(orgIamBasicRoles{}, res("google_organization_iam_binding", "o",
		map[string]ir.Value{"role": ks("roles/compute.viewer", 3)})))
	mustQuiet(t, runRule(orgIamBasicRoles{}, res("google_organization_iam_binding", "o",
		map[string]ir.Value{"role": ku(3)})))

	// 149: folder basic roles
	f = mustFinding(t, runRule(folderIamBasicRoles{}, res("google_folder_iam_member", "f",
		map[string]ir.Value{
			"role":   ks("roles/viewer", 3),
			"member": ks("user:a@example.com", 4),
		})), "AEGIS-GCP-149")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("149: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(folderIamBasicRoles{}, res("google_folder_iam_binding", "f",
		map[string]ir.Value{"role": ks("roles/logging.viewer", 3)})))
	mustQuiet(t, runRule(folderIamBasicRoles{}, res("google_folder_iam_binding", "f", nil)))

	// 150: deleted principal
	mustFinding(t, runRule(iamDeletedPrincipal{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{
			"role":    ks("roles/viewer", 3),
			"members": strList(4, "deleted:serviceAccount:old@proj.iam.gserviceaccount.com"),
		})), "AEGIS-GCP-150")
	mustFinding(t, runRule(iamDeletedPrincipal{}, res("google_folder_iam_member", "f",
		map[string]ir.Value{
			"role":   ks("roles/viewer", 3),
			"member": ks("deleted:user:gone@example.com", 4),
		})), "AEGIS-GCP-150")
	mustQuiet(t, runRule(iamDeletedPrincipal{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{
			"role":    ks("roles/viewer", 3),
			"members": strList(4, "user:a@example.com"),
		})))
	mustQuiet(t, runRule(iamDeletedPrincipal{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{
			"role":    ks("roles/viewer", 3),
			"members": ku(4),
		})))

	// 151: authoritative SA IAM policy
	mustFinding(t, runRule(saIamAuthoritativePolicy{},
		res("google_service_account_iam_policy", "s", nil)), "AEGIS-GCP-151")
	mustQuiet(t, runRule(saIamAuthoritativePolicy{},
		res("google_service_account_iam_binding", "b", nil)))

	// 152: Project IAM Admin grant
	f = mustFinding(t, runRule(iamProjectIamAdminGrant{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{
			"role":    ks("roles/resourcemanager.projectIamAdmin", 3),
			"members": strList(4, "user:a@example.com"),
		})), "AEGIS-GCP-152")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("152: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(iamProjectIamAdminGrant{}, res("google_project_iam_member", "m",
		map[string]ir.Value{"role": ks("roles/viewer", 3)})))
	mustQuiet(t, runRule(iamProjectIamAdminGrant{}, res("google_project_iam_binding", "b",
		map[string]ir.Value{"role": ku(3)})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-153..162: Cloud SQL
// ---------------------------------------------------------------------------

func sqlSettingsRes(attrs map[string]ir.Value) ir.Resource {
	return res("google_sql_database_instance", "db", attrs)
}

func TestGCP6SQL(t *testing.T) {
	// 153: no Query Insights
	mustFinding(t, runRule(sqlNoQueryInsights{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("tier", ks("db-f1-micro", 3))),
	})), "AEGIS-GCP-153")
	mustQuiet(t, runRule(sqlNoQueryInsights{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("insights_config",
			blks(3, blk("query_insights_enabled", kv(true, 4))))),
	})))
	mustQuiet(t, runRule(sqlNoQueryInsights{}, sqlSettingsRes(map[string]ir.Value{
		"settings": ku(2),
	})))
	mustQuiet(t, runRule(sqlNoQueryInsights{}, sqlSettingsRes(nil)))

	// 154: not highly available
	mustFinding(t, runRule(sqlNotHighlyAvailable{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("tier", ks("db-f1-micro", 3))),
	})), "AEGIS-GCP-154")
	mustFinding(t, runRule(sqlNotHighlyAvailable{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("availability_type", ks("ZONAL", 3))),
	})), "AEGIS-GCP-154")
	mustQuiet(t, runRule(sqlNotHighlyAvailable{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("availability_type", ks("REGIONAL", 3))),
	})))
	mustQuiet(t, runRule(sqlNotHighlyAvailable{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("availability_type", ku(3))),
	})))

	// 155: SQL user password in config
	mustFinding(t, runRule(sqlUserPasswordInConfig{}, res("google_sql_user", "u",
		map[string]ir.Value{"password": ks("s3cret", 3)})), "AEGIS-GCP-155")
	mustQuiet(t, runRule(sqlUserPasswordInConfig{}, res("google_sql_user", "u", nil)))
	mustQuiet(t, runRule(sqlUserPasswordInConfig{}, res("google_sql_user", "u",
		map[string]ir.Value{"password": ks("", 3)})))
	mustQuiet(t, runRule(sqlUserPasswordInConfig{}, res("google_sql_user", "u",
		map[string]ir.Value{"password": ku(3)})))

	// 156: low backup retention
	mustFinding(t, runRule(sqlLowBackupRetention{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("backup_retention_settings",
				blks(4, blk("retained_backups", kn(3, 5))))))),
	})), "AEGIS-GCP-156")
	mustQuiet(t, runRule(sqlLowBackupRetention{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("backup_retention_settings",
				blks(4, blk("retained_backups", kn(14, 5))))))),
	})))
	mustQuiet(t, runRule(sqlLowBackupRetention{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("backup_retention_settings",
				blks(4, blk("retained_backups", ku(5))))))),
	})))
	mustQuiet(t, runRule(sqlLowBackupRetention{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("tier", ks("db-f1-micro", 3))),
	})))

	// 157: no password validation policy
	mustFinding(t, runRule(sqlNoPasswordValidationPolicy{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("tier", ks("db-f1-micro", 3))),
	})), "AEGIS-GCP-157")
	mustQuiet(t, runRule(sqlNoPasswordValidationPolicy{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("password_validation_policy",
			blks(3, blk("min_length", kn(12, 4))))),
	})))
	mustQuiet(t, runRule(sqlNoPasswordValidationPolicy{}, sqlSettingsRes(map[string]ir.Value{
		"settings": ku(2),
	})))

	// 158: root password in config
	mustFinding(t, runRule(sqlRootPasswordInConfig{}, sqlSettingsRes(map[string]ir.Value{
		"root_password": ks("s3cret", 2),
	})), "AEGIS-GCP-158")
	mustQuiet(t, runRule(sqlRootPasswordInConfig{}, sqlSettingsRes(nil)))
	mustQuiet(t, runRule(sqlRootPasswordInConfig{}, sqlSettingsRes(map[string]ir.Value{
		"root_password": ku(2),
	})))

	// 159: short transaction log retention
	mustFinding(t, runRule(sqlShortTransactionLogRetention{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("transaction_log_retention_days", kn(3, 4))))),
	})), "AEGIS-GCP-159")
	mustQuiet(t, runRule(sqlShortTransactionLogRetention{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("transaction_log_retention_days", kn(7, 4))))),
	})))
	mustQuiet(t, runRule(sqlShortTransactionLogRetention{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("transaction_log_retention_days", ku(4))))),
	})))
	mustQuiet(t, runRule(sqlShortTransactionLogRetention{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("tier", ks("db-f1-micro", 3))),
	})))

	// 160: no binary log
	mustFinding(t, runRule(sqlNoBinaryLog{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("binary_log_enabled", kv(false, 4))))),
	})), "AEGIS-GCP-160")
	mustFinding(t, runRule(sqlNoBinaryLog{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("enabled", kv(true, 4))))),
	})), "AEGIS-GCP-160")
	mustQuiet(t, runRule(sqlNoBinaryLog{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("binary_log_enabled", kv(true, 4))))),
	})))
	mustQuiet(t, runRule(sqlNoBinaryLog{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("backup_configuration",
			blks(3, blk("binary_log_enabled", ku(4))))),
	})))
	mustQuiet(t, runRule(sqlNoBinaryLog{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("tier", ks("db-f1-micro", 3))),
	})))

	// 161: weak password encryption flag
	mustFinding(t, runRule(sqlWeakPasswordEncryption{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("database_flags",
			blks(3, blk("name", ks("password_encryption", 4),
				"value", ks("md5", 5))))),
	})), "AEGIS-GCP-161")
	mustQuiet(t, runRule(sqlWeakPasswordEncryption{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("database_flags",
			blks(3, blk("name", ks("password_encryption", 4),
				"value", ks("scram-sha-256", 5))))),
	})))
	mustQuiet(t, runRule(sqlWeakPasswordEncryption{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("database_flags",
			blks(3, blk("name", ks("password_encryption", 4),
				"value", ku(5))))),
	})))
	mustQuiet(t, runRule(sqlWeakPasswordEncryption{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("tier", ks("db-f1-micro", 3))),
	})))

	// 162: permissive SSL mode
	f := mustFinding(t, runRule(sqlSSLModePermissive{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("ip_configuration",
			blks(3, blk("ssl_mode", ks("ALLOW_UNENCRYPTED_AND_ENCRYPTED", 4))))),
	})), "AEGIS-GCP-162")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("162: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(sqlSSLModePermissive{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("ip_configuration",
			blks(3, blk("ssl_mode", ks("ENCRYPTED_ONLY", 4))))),
	})))
	mustQuiet(t, runRule(sqlSSLModePermissive{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("ip_configuration",
			blks(3, blk("ssl_mode", ku(4))))),
	})))
	mustQuiet(t, runRule(sqlSSLModePermissive{}, sqlSettingsRes(map[string]ir.Value{
		"settings": blks(2, blk("tier", ks("db-f1-micro", 3))),
	})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-163..172: GKE
// ---------------------------------------------------------------------------

func TestGCP6GKE(t *testing.T) {
	// 163: no security posture
	mustFinding(t, runRule(gkeNoSecurityPosture{},
		res("google_container_cluster", "c", nil)), "AEGIS-GCP-163")
	mustFinding(t, runRule(gkeNoSecurityPosture{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"security_posture_config": blks(2, blk("vulnerability_mode", ks("DISABLED", 3))),
		})), "AEGIS-GCP-163")
	mustQuiet(t, runRule(gkeNoSecurityPosture{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"security_posture_config": blks(2, blk("vulnerability_mode", ks("BASIC", 3))),
		})))
	mustQuiet(t, runRule(gkeNoSecurityPosture{}, res("google_container_cluster", "c",
		map[string]ir.Value{"security_posture_config": ku(2)})))

	// 164: legacy metadata endpoints (cluster)
	mustFinding(t, runRule(gkeLegacyMetadataEndpoints{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"node_config": blks(2, blk("metadata", metaMap(3))),
		})), "AEGIS-GCP-164")
	mustFinding(t, runRule(gkeLegacyMetadataEndpoints{},
		res("google_container_cluster", "c", nil)), "AEGIS-GCP-164")
	mustQuiet(t, runRule(gkeLegacyMetadataEndpoints{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"node_config": blks(2, blk("metadata", metaMap(3, "disable-legacy-endpoints", "true"))),
		})))
	mustQuiet(t, runRule(gkeLegacyMetadataEndpoints{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"node_config": blks(2, blk("metadata", ku(3))),
		})))

	// 165: no database encryption
	mustFinding(t, runRule(gkeNoDatabaseEncryption{},
		res("google_container_cluster", "c", nil)), "AEGIS-GCP-165")
	mustQuiet(t, runRule(gkeNoDatabaseEncryption{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"database_encryption": blks(2, blk("state", ks("ENCRYPTED", 3))),
		})))
	mustQuiet(t, runRule(gkeNoDatabaseEncryption{}, res("google_container_cluster", "c",
		map[string]ir.Value{"database_encryption": ku(2)})))

	// 166: no authenticator groups
	mustFinding(t, runRule(gkeNoAuthenticatorGroups{},
		res("google_container_cluster", "c", nil)), "AEGIS-GCP-166")
	mustQuiet(t, runRule(gkeNoAuthenticatorGroups{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"authenticator_groups_config": blks(2, blk("security_group", ks("g@x.y", 3))),
		})))
	mustQuiet(t, runRule(gkeNoAuthenticatorGroups{}, res("google_container_cluster", "c",
		map[string]ir.Value{"authenticator_groups_config": ku(2)})))

	// 167: alpha cluster
	f := mustFinding(t, runRule(gkeAlphaCluster{}, res("google_container_cluster", "c",
		map[string]ir.Value{"enable_kubernetes_alpha": kv(true, 2)})), "AEGIS-GCP-167")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("167: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(gkeAlphaCluster{}, res("google_container_cluster", "c",
		map[string]ir.Value{"enable_kubernetes_alpha": kv(false, 2)})))
	mustQuiet(t, runRule(gkeAlphaCluster{}, res("google_container_cluster", "c", nil)))
	mustQuiet(t, runRule(gkeAlphaCluster{}, res("google_container_cluster", "c",
		map[string]ir.Value{"enable_kubernetes_alpha": ku(2)})))

	// 168: no VPC-native
	mustFinding(t, runRule(gkeNoVPCNative{},
		res("google_container_cluster", "c", nil)), "AEGIS-GCP-168")
	mustQuiet(t, runRule(gkeNoVPCNative{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"ip_allocation_policy": blks(2, blk("cluster_ipv4_cidr_block", ks("10.0.0.0/14", 3))),
		})))
	mustQuiet(t, runRule(gkeNoVPCNative{}, res("google_container_cluster", "c",
		map[string]ir.Value{"ip_allocation_policy": ku(2)})))

	// 169: service external IPs
	mustFinding(t, runRule(gkeServiceExternalIPs{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"service_external_ips_config": blks(2, blk("enabled", kv(true, 3))),
		})), "AEGIS-GCP-169")
	mustQuiet(t, runRule(gkeServiceExternalIPs{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"service_external_ips_config": blks(2, blk("enabled", kv(false, 3))),
		})))
	mustQuiet(t, runRule(gkeServiceExternalIPs{},
		res("google_container_cluster", "c", nil)))
	mustQuiet(t, runRule(gkeServiceExternalIPs{}, res("google_container_cluster", "c",
		map[string]ir.Value{"service_external_ips_config": ku(2)})))

	// 170: master authorized networks open
	f = mustFinding(t, runRule(gkeMasterAuthNetworksOpen{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"master_authorized_networks_config": blks(2, blk("cidr_blocks",
				blks(3, blk("cidr_block", ks("0.0.0.0/0", 4))))),
		})), "AEGIS-GCP-170")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("170: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(gkeMasterAuthNetworksOpen{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"master_authorized_networks_config": blks(2, blk("cidr_blocks",
				blks(3, blk("cidr_block", ks("10.0.0.0/8", 4))))),
		})))
	mustQuiet(t, runRule(gkeMasterAuthNetworksOpen{},
		res("google_container_cluster", "c", nil)))
	mustQuiet(t, runRule(gkeMasterAuthNetworksOpen{}, res("google_container_cluster", "c",
		map[string]ir.Value{"master_authorized_networks_config": ku(2)})))

	// 171: legacy metadata endpoints (node pool)
	mustFinding(t, runRule(gkeNodePoolLegacyMetadata{}, res("google_container_node_pool", "p",
		map[string]ir.Value{
			"node_config": blks(2, blk("metadata", metaMap(3, "disable-legacy-endpoints", "false"))),
		})), "AEGIS-GCP-171")
	mustQuiet(t, runRule(gkeNodePoolLegacyMetadata{}, res("google_container_node_pool", "p",
		map[string]ir.Value{
			"node_config": blks(2, blk("metadata", metaMap(3, "disable-legacy-endpoints", "true"))),
		})))
	mustQuiet(t, runRule(gkeNodePoolLegacyMetadata{}, res("google_container_node_pool", "p",
		map[string]ir.Value{
			"node_config": blks(2, blk("metadata", ku(3))),
		})))

	// 172: node boot disk CMEK
	mustFinding(t, runRule(gkeNodeBootDiskNoCMEK{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"node_config": blks(2, blk("machine_type", ks("e2-medium", 3))),
		})), "AEGIS-GCP-172")
	mustFinding(t, runRule(gkeNodeBootDiskNoCMEK{},
		res("google_container_node_pool", "p", nil)), "AEGIS-GCP-172")
	mustQuiet(t, runRule(gkeNodeBootDiskNoCMEK{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"node_config": blks(2, blk("boot_disk_kms_key", ks("projects/p/locations/l/keyRings/k/cryptoKeys/k", 3))),
		})))
	mustQuiet(t, runRule(gkeNodeBootDiskNoCMEK{}, res("google_container_cluster", "c",
		map[string]ir.Value{
			"node_config": blks(2, blk("boot_disk_kms_key", ku(3))),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-173..182: Compute
// ---------------------------------------------------------------------------

func TestGCP6Compute(t *testing.T) {
	// 173: no Confidential VM
	mustFinding(t, runRule(computeNoConfidentialVM{},
		res("google_compute_instance", "i", nil)), "AEGIS-GCP-173")
	mustQuiet(t, runRule(computeNoConfidentialVM{}, res("google_compute_instance", "i",
		map[string]ir.Value{
			"confidential_instance_config": blks(2, blk("enable_confidential_compute", kv(true, 3))),
		})))
	mustQuiet(t, runRule(computeNoConfidentialVM{}, res("google_compute_instance", "i",
		map[string]ir.Value{"confidential_instance_config": ku(2)})))

	// 174: vTPM disabled
	mustFinding(t, runRule(computeVTPMOff{}, res("google_compute_instance", "i",
		map[string]ir.Value{
			"shielded_instance_config": blks(2, blk("enable_vtpm", kv(false, 3))),
		})), "AEGIS-GCP-174")
	mustQuiet(t, runRule(computeVTPMOff{}, res("google_compute_instance", "i",
		map[string]ir.Value{
			"shielded_instance_config": blks(2, blk("enable_vtpm", kv(true, 3))),
		})))
	mustQuiet(t, runRule(computeVTPMOff{},
		res("google_compute_instance", "i", nil)))
	mustQuiet(t, runRule(computeVTPMOff{}, res("google_compute_instance", "i",
		map[string]ir.Value{
			"shielded_instance_config": blks(2, blk("enable_vtpm", ku(3))),
		})))

	// 175: integrity monitoring disabled
	mustFinding(t, runRule(computeIntegrityMonOff{}, res("google_compute_instance", "i",
		map[string]ir.Value{
			"shielded_instance_config": blks(2, blk("enable_integrity_monitoring", kv(false, 3))),
		})), "AEGIS-GCP-175")
	mustQuiet(t, runRule(computeIntegrityMonOff{}, res("google_compute_instance", "i",
		map[string]ir.Value{
			"shielded_instance_config": blks(2, blk("enable_integrity_monitoring", kv(true, 3))),
		})))
	mustQuiet(t, runRule(computeIntegrityMonOff{},
		res("google_compute_instance", "i", nil)))

	// 176: OS Login 2FA
	mustFinding(t, runRule(computeNoOSLogin2FA{}, res("google_compute_instance", "i",
		map[string]ir.Value{
			"metadata": metaMap(2, "enable-oslogin-2fa", "FALSE"),
		})), "AEGIS-GCP-176")
	mustQuiet(t, runRule(computeNoOSLogin2FA{}, res("google_compute_instance", "i",
		map[string]ir.Value{
			"metadata": metaMap(2, "enable-oslogin-2fa", "TRUE"),
		})))
	mustQuiet(t, runRule(computeNoOSLogin2FA{},
		res("google_compute_instance", "i", nil)))
	mustQuiet(t, runRule(computeNoOSLogin2FA{}, res("google_compute_instance", "i",
		map[string]ir.Value{"metadata": ku(2)})))

	// 177: template without secure boot
	mustFinding(t, runRule(instanceTemplateNoSecureBoot{},
		res("google_compute_instance_template", "t", nil)), "AEGIS-GCP-177")
	mustFinding(t, runRule(instanceTemplateNoSecureBoot{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{
			"shielded_instance_config": blks(2, blk("enable_secure_boot", kv(false, 3))),
		})), "AEGIS-GCP-177")
	mustQuiet(t, runRule(instanceTemplateNoSecureBoot{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{
			"shielded_instance_config": blks(2, blk("enable_secure_boot", kv(true, 3))),
		})))
	mustQuiet(t, runRule(instanceTemplateNoSecureBoot{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{"shielded_instance_config": ku(2)})))
	// instance rule must not fire on templates and vice versa
	mustQuiet(t, runRule(instanceNoSecureBoot{}, res("google_compute_instance_template", "t", nil)))

	// 178: template with public IP
	f := mustFinding(t, runRule(instanceTemplatePublicIP{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{
			"network_interface": blks(2, blk("network", ks("default", 3),
				"access_config", blks(4, blk()))),
		})), "AEGIS-GCP-178")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("178: wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(instanceTemplatePublicIP{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{
			"network_interface": blks(2, blk("network", ks("default", 3))),
		})))
	mustQuiet(t, runRule(instanceTemplatePublicIP{},
		res("google_compute_instance_template", "t", nil)))

	// 179: template without OS Login
	mustFinding(t, runRule(instanceTemplateNoOSLogin{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{
			"metadata": metaMap(2, "enable-oslogin", "FALSE"),
		})), "AEGIS-GCP-179")
	mustQuiet(t, runRule(instanceTemplateNoOSLogin{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{
			"metadata": metaMap(2, "enable-oslogin", "TRUE"),
		})))
	mustQuiet(t, runRule(instanceTemplateNoOSLogin{},
		res("google_compute_instance_template", "t", nil)))

	// 180: template serial port
	mustFinding(t, runRule(instanceTemplateSerialPort{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{
			"metadata": metaMap(2, "serial-port-enable", "TRUE"),
		})), "AEGIS-GCP-180")
	mustQuiet(t, runRule(instanceTemplateSerialPort{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{
			"metadata": metaMap(2, "serial-port-enable", "FALSE"),
		})))
	mustQuiet(t, runRule(instanceTemplateSerialPort{},
		res("google_compute_instance_template", "t", nil)))
	mustQuiet(t, runRule(instanceTemplateSerialPort{}, res("google_compute_instance_template", "t",
		map[string]ir.Value{"metadata": ku(2)})))

	// 181: snapshot CMEK
	mustFinding(t, runRule(snapshotNoCMEK{},
		res("google_compute_snapshot", "s", nil)), "AEGIS-GCP-181")
	mustQuiet(t, runRule(snapshotNoCMEK{}, res("google_compute_snapshot", "s",
		map[string]ir.Value{
			"snapshot_encryption_key": blks(2, blk("kms_key_self_link", ks("k", 3))),
		})))
	mustQuiet(t, runRule(snapshotNoCMEK{}, res("google_compute_snapshot", "s",
		map[string]ir.Value{"snapshot_encryption_key": ku(2)})))

	// 182: image CMEK
	mustFinding(t, runRule(imageNoCMEK{},
		res("google_compute_image", "i", nil)), "AEGIS-GCP-182")
	mustQuiet(t, runRule(imageNoCMEK{}, res("google_compute_image", "i",
		map[string]ir.Value{
			"image_encryption_key": blks(2, blk("kms_key_self_link", ks("k", 3))),
		})))
	mustQuiet(t, runRule(imageNoCMEK{}, res("google_compute_image", "i",
		map[string]ir.Value{"image_encryption_key": ku(2)})))
}
