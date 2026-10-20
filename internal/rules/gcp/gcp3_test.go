package gcp

import (
	"fmt"
	"testing"

	"aegis/internal/ir"
)

// sl builds a known string list value.
func sl(line int, ss ...string) ir.Value {
	items := make([]ir.Value, len(ss))
	for i, s := range ss {
		items[i] = ks(s, line)
	}
	return ir.Value{Raw: items, Known: true, Span: spanAt(line)}
}

// --- 025: bucket CMEK ---
func TestGCP025_NoCMEKFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{})
	mustFinding(t, runRule(bucketNoCMEK{}, r), "AEGIS-GCP-025")
}
func TestGCP025_CMEKQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{
		"encryption": blks(3, blk("default_kms_key_name", ks("k", 4))),
	})
	if len(runRule(bucketNoCMEK{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 026: bucket public ACL ---
func TestGCP026_PublicACLFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"predefined_acl": ks("publicRead", 3)})
	mustFinding(t, runRule(bucketPublicACL{}, r), "AEGIS-GCP-026")
}
func TestGCP026_PrivateQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"predefined_acl": ks("private", 3)})
	if len(runRule(bucketPublicACL{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 027: bucket logging ---
func TestGCP027_NoLoggingFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{})
	mustFinding(t, runRule(bucketNoLogging{}, r), "AEGIS-GCP-027")
}
func TestGCP027_LoggingQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"logging": blks(3, blk())})
	if len(runRule(bucketNoLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 028: bucket website ---
func TestGCP028_WebsiteFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"website": blks(3, blk())})
	mustFinding(t, runRule(bucketWebsiteEnabled{}, r), "AEGIS-GCP-028")
}
func TestGCP028_NoWebsiteQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{})
	if len(runRule(bucketWebsiteEnabled{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 029: CORS wildcard ---
func TestGCP029_WildcardCORSFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{
		"cors": blks(3, blk("origin", sl(4, "*"))),
	})
	mustFinding(t, runRule(bucketWildcardCORS{}, r), "AEGIS-GCP-029")
}
func TestGCP029_SpecificCORSQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{
		"cors": blks(3, blk("origin", sl(4, "https://example.com"))),
	})
	if len(runRule(bucketWildcardCORS{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 030: force_destroy ---
func TestGCP030_ForceDestroyFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"force_destroy": kv(true, 3)})
	mustFinding(t, runRule(bucketForceDestroy{}, r), "AEGIS-GCP-030")
}
func TestGCP030_NoForceDestroyQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"force_destroy": kv(false, 3)})
	if len(runRule(bucketForceDestroy{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 031: lifecycle ---
func TestGCP031_NoLifecycleFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{})
	mustFinding(t, runRule(bucketNoLifecycle{}, r), "AEGIS-GCP-031")
}

// --- 032: public access prevention ---
func TestGCP032_NoPAPFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{})
	mustFinding(t, runRule(bucketNoPAP{}, r), "AEGIS-GCP-032")
}
func TestGCP032_PAPQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"public_access_prevention": ks("enforced", 3)})
	if len(runRule(bucketNoPAP{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 033: BQ public access ---
func TestGCP033_PublicAccessFires(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("special_group", ks("allUsers", 4))),
	})
	mustFinding(t, runRule(bqPublicAccess{}, r), "AEGIS-GCP-033")
}
func TestGCP033_PrivateQuiet(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("special_group", ks("projectOwners", 4))),
	})
	if len(runRule(bqPublicAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 034: BQ table expiration ---
func TestGCP034_NoExpirationFires(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{})
	mustFinding(t, runRule(bqNoTableExpiration{}, r), "AEGIS-GCP-034")
}

// --- 035: BQ table CMEK ---
func TestGCP035_NoCMEKFires(t *testing.T) {
	r := res("google_bigquery_table", "tb", map[string]ir.Value{})
	mustFinding(t, runRule(bqTableNoCMEK{}, r), "AEGIS-GCP-035")
}

// --- 036: BQ primitive role ---
func TestGCP036_PrimitiveFires(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("role", ks("roles/editor", 4))),
	})
	mustFinding(t, runRule(bqPrimitiveRole{}, r), "AEGIS-GCP-036")
}
func TestGCP036_GranularQuiet(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{
		"access": blks(3, blk("role", ks("roles/bigquery.dataViewer", 4))),
	})
	if len(runRule(bqPrimitiveRole{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 037: BQ deletion protection ---
func TestGCP037_NoProtectionFires(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{"deletion_protection": kv(false, 3)})
	mustFinding(t, runRule(bqNoDeletionProtection{}, r), "AEGIS-GCP-037")
}

// --- 038: BQ IAM public ---
func TestGCP038_PublicFires(t *testing.T) {
	r := res("google_bigquery_dataset_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/bigquery.dataViewer", 3), "members": sl(4, "allUsers"),
	})
	mustFinding(t, runRule(bqViewerAllUsers{}, r), "AEGIS-GCP-038")
}
func TestGCP038_PrivateQuiet(t *testing.T) {
	r := res("google_bigquery_dataset_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/bigquery.dataViewer", 3), "members": sl(4, "user:a@b.com"),
	})
	if len(runRule(bqViewerAllUsers{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-038: expected 0 findings")
	}
}

// --- 039: SQL PITR ---
func TestGCP039_NoPITRFires(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"backup_configuration": blks(3, blk("enabled", kv(true, 4))),
	})
	mustFinding(t, runRule(sqlNoPITR{}, r), "AEGIS-GCP-039")
}
func TestGCP039_PITRQuiet(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"backup_configuration": blks(3, blk("enabled", kv(true, 4), "point_in_time_recovery_enabled", kv(true, 4))),
	})
	if len(runRule(sqlNoPITR{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 040: SQL open networks ---
func TestGCP040_OpenNetworksFires(t *testing.T) {
	ipc := ir.Value{Raw: []ir.Value{{Raw: map[string]ir.Value{
		"authorized_networks": blks(6, blk("value", ks("0.0.0.0/0", 7))),
	}, Known: true, Span: spanAt(5)}}, Known: true, Span: spanAt(4)}
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(3, blk("ip_configuration", ipc)),
	})
	mustFinding(t, runRule(sqlOpenAuthorizedNetworks{}, r), "AEGIS-GCP-040")
}
func TestGCP040_RestrictedNetworksQuiet(t *testing.T) {
	ipc := ir.Value{Raw: []ir.Value{{Raw: map[string]ir.Value{
		"authorized_networks": blks(6, blk("value", ks("10.0.0.0/8", 7))),
	}, Known: true, Span: spanAt(5)}}, Known: true, Span: spanAt(4)}
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(3, blk("ip_configuration", ipc)),
	})
	if len(runRule(sqlOpenAuthorizedNetworks{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-040: expected 0 findings")
	}
}

// --- 041: SQL wildcard host ---
func TestGCP041_WildcardHostFires(t *testing.T) {
	r := res("google_sql_user", "u", map[string]ir.Value{"host": ks("%", 3)})
	mustFinding(t, runRule(sqlWildcardUserHost{}, r), "AEGIS-GCP-041")
}
func TestGCP041_SpecificHostQuiet(t *testing.T) {
	r := res("google_sql_user", "u", map[string]ir.Value{"host": ks("10.0.0.5", 3)})
	if len(runRule(sqlWildcardUserHost{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 042: SQL maint window ---
func TestGCP042_NoMaintWindowFires(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(3, blk()),
	})
	mustFinding(t, runRule(sqlNoMaintWindow{}, r), "AEGIS-GCP-042")
}

// --- 043: SQL old version ---
func TestGCP043_OldVersionFires(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{"database_version": ks("MYSQL_5_7", 3)})
	mustFinding(t, runRule(sqlOldVersion{}, r), "AEGIS-GCP-043")
}
func TestGCP043_NewVersionQuiet(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{"database_version": ks("MYSQL_8_0", 3)})
	if len(runRule(sqlOldVersion{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 044: SQL IAM auth ---
func TestGCP044_NoIAMAuthFires(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(3, blk()),
	})
	mustFinding(t, runRule(sqlNoIAMAuth{}, r), "AEGIS-GCP-044")
}

// --- 045: SQL local_infile ---
func TestGCP045_LocalInfileFires(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(3, blk("database_flags", blks(4,
			blk("name", ks("local_infile", 5), "value", ks("on", 5))))),
	})
	mustFinding(t, runRule(sqlLocalInfile{}, r), "AEGIS-GCP-045")
}

// --- 046: SQL log_disconnections ---
func TestGCP046_NoLogDisconnectionsFires(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(3, blk()),
	})
	mustFinding(t, runRule(sqlNoLogDisconnections{}, r), "AEGIS-GCP-046")
}

// --- 047: GKE workload identity ---
func TestGCP047_NoWIFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeNoWorkloadIdentity{}, r), "AEGIS-GCP-047")
}
func TestGCP047_WIQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"workload_identity_config": blks(3, blk("workload_pool", ks("proj.svc.id.goog", 4))),
	})
	if len(runRule(gkeNoWorkloadIdentity{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-047: expected 0 findings")
	}
}

// --- 048: GKE binary auth ---
// --- 049: GKE auto-upgrade ---
func TestGCP049_NoAutoUpgradeFires(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{
		"management": blks(3, blk("auto_upgrade", kv(false, 4))),
	})
	mustFinding(t, runRule(gkeNoAutoUpgrade{}, r), "AEGIS-GCP-049")
}

// --- 050: GKE auto-repair ---
func TestGCP050_NoAutoRepairFires(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{
		"management": blks(3, blk("auto_repair", kv(false, 4))),
	})
	mustFinding(t, runRule(gkeNoAutoRepair{}, r), "AEGIS-GCP-050")
}

// --- 051: GKE basic auth ---
func TestGCP051_BasicAuthFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"master_auth": blks(3, blk("username", ks("admin", 4))),
	})
	mustFinding(t, runRule(gkeBasicAuth{}, r), "AEGIS-GCP-051")
}
func TestGCP051_NoBasicAuthQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"master_auth": blks(3, blk("client_certificate_config",
			blks(4, blk("issue_client_certificate", kv(false, 5))))),
	})
	if len(runRule(gkeBasicAuth{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-051: expected 0 findings")
	}
}

// --- 052: GKE client cert ---
func TestGCP052_ClientCertFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"master_auth": blks(3, blk("client_certificate_config",
			blks(4, blk("issue_client_certificate", kv(true, 5))))),
	})
	mustFinding(t, runRule(gkeClientCert{}, r), "AEGIS-GCP-052")
}
func TestGCP052_NoClientCertQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"master_auth": blks(3, blk("client_certificate_config",
			blks(4, blk("issue_client_certificate", kv(false, 5))))),
	})
	if len(runRule(gkeClientCert{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-052: expected 0 findings")
	}
}

// --- 053: GKE default SA ---
func TestGCP053_DefaultSAFires(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{
		"node_config": blks(3, blk("oauth_scopes", sl(4, "https://www.googleapis.com/auth/cloud-platform"))),
	})
	mustFinding(t, runRule(gkeDefaultSAFullScope{}, r), "AEGIS-GCP-053")
}
func TestGCP053_DedicatedSAQuiet(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{
		"node_config": blks(3, blk(
			"service_account", ks("node-sa@proj.iam.gserviceaccount.com", 4),
			"oauth_scopes", sl(4, "https://www.googleapis.com/auth/logging.write"),
		)),
	})
	if len(runRule(gkeDefaultSAFullScope{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-053: expected 0 findings")
	}
}

// --- 054: GKE intranode visibility ---
func TestGCP054_NoVisibilityFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"enable_intranode_visibility": kv(false, 3)})
	mustFinding(t, runRule(gkeNoIntranodeVisibility{}, r), "AEGIS-GCP-054")
}

// --- 055: GKE shielded nodes ---
func TestGCP055_NoShieldedFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeNoShieldedNodes{}, r), "AEGIS-GCP-055")
}

// --- 056: GKE confidential nodes ---
func TestGCP056_NoConfidentialFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"node_config": blks(3, blk()),
	})
	mustFinding(t, runRule(gkeNoConfidentialNodes{}, r), "AEGIS-GCP-056")
}

// --- 057: IP forwarding ---
func TestGCP057_IPForwardFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{"can_ip_forward": kv(true, 3)})
	mustFinding(t, runRule(instanceIPForward{}, r), "AEGIS-GCP-057")
}

// --- 058: serial port ---
func TestGCP058_SerialPortFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"metadata": ir.Value{Raw: map[string]ir.Value{"serial-port-enable": ks("true", 4)}, Known: true, Span: spanAt(3)},
	})
	mustFinding(t, runRule(instanceSerialPort{}, r), "AEGIS-GCP-058")
}

// --- 059: secure boot ---
func TestGCP059_NoSecureBootFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{})
	mustFinding(t, runRule(instanceNoSecureBoot{}, r), "AEGIS-GCP-059")
}

// --- 060: OS Login ---
func TestGCP060_NoOSLoginFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"metadata": ir.Value{Raw: map[string]ir.Value{"enable-oslogin": ks("FALSE", 4)}, Known: true, Span: spanAt(3)},
	})
	mustFinding(t, runRule(instanceNoOSLogin{}, r), "AEGIS-GCP-060")
}

// --- 061: boot disk CMEK ---
func TestGCP061_NoDiskCMEKFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"boot_disk": blks(3, blk("initialize_params", blks(4, blk()))),
	})
	mustFinding(t, runRule(instanceDiskNoCMEK{}, r), "AEGIS-GCP-061")
}
func TestGCP061_DiskCMEKQuiet(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"boot_disk": blks(3, blk("initialize_params",
			blks(4, blk("kms_key_self_link", ks("projects/p/locations/l/keyRings/r/cryptoKeys/k", 5))))),
	})
	if len(runRule(instanceDiskNoCMEK{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-061: expected 0 findings")
	}
}

// --- 062: default SA ---
func TestGCP062_DefaultSAFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"service_account": blks(3, blk()),
	})
	mustFinding(t, runRule(instanceDefaultSA{}, r), "AEGIS-GCP-062")
}

// --- 064: deletion protection ---
func TestGCP064_NoDeletionProtectionFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{"deletion_protection": kv(false, 3)})
	mustFinding(t, runRule(instanceNoDeletionProtection{}, r), "AEGIS-GCP-064")
}

// --- 065: project SSH keys ---
func TestGCP065_ProjectKeysFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"metadata": ir.Value{Raw: map[string]ir.Value{"block-project-ssh-keys": ks("false", 4)}, Known: true, Span: spanAt(3)},
	})
	mustFinding(t, runRule(instanceProjectSSHKeys{}, r), "AEGIS-GCP-065")
}

func TestGCP065_NoMetadataFires(t *testing.T) {
	// No metadata block: project-wide SSH keys are enabled by default.
	r := res("google_compute_instance", "i", map[string]ir.Value{})
	mustFinding(t, runRule(instanceProjectSSHKeys{}, r), "AEGIS-GCP-065")
}

func TestGCP065_MetadataKeyAbsentFires(t *testing.T) {
	// Metadata block without the key: defaults to accepting project keys.
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"metadata": ir.Value{Raw: map[string]ir.Value{"enable-oslogin": ks("TRUE", 4)}, Known: true, Span: spanAt(3)},
	})
	mustFinding(t, runRule(instanceProjectSSHKeys{}, r), "AEGIS-GCP-065")
}

func TestGCP065_KeyTrueQuiet(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"metadata": ir.Value{Raw: map[string]ir.Value{"block-project-ssh-keys": ks("TRUE", 4)}, Known: true, Span: spanAt(3)},
	})
	if len(runRule(instanceProjectSSHKeys{}, r)) != 0 {
		t.Fatal("expected 0 findings when block-project-ssh-keys is TRUE")
	}
}

// --- 066: disk CMEK ---
func TestGCP066_DiskNoCMEKFires(t *testing.T) {
	r := res("google_compute_disk", "d", map[string]ir.Value{})
	mustFinding(t, runRule(computeDiskNoCMEK{}, r), "AEGIS-GCP-066")
}

// --- 067: RDP open ---
func TestGCP067_RDPOpenFires(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": sl(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5), "ports", sl(5, "3389"))),
	})
	mustFinding(t, runRule(firewallOpenRDP{}, r), "AEGIS-GCP-067")
}
func TestGCP067_ScopedPortsQuiet(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": sl(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5), "ports", sl(5, "443"))),
	})
	if len(runRule(firewallOpenRDP{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-067: expected 0 findings")
	}
}

// --- 068: all ports ---
func TestGCP068_AllPortsFires(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": sl(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5), "ports", sl(5, "0-65535"))),
	})
	mustFinding(t, runRule(firewallAllPorts{}, r), "AEGIS-GCP-068")
}
func TestGCP068_ScopedPortsQuiet(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": sl(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5), "ports", sl(5, "443"))),
	})
	if len(runRule(firewallAllPorts{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-068: expected 0 findings")
	}
}

// --- 069: firewall logging ---
func TestGCP069_NoLoggingFires(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{})
	mustFinding(t, runRule(firewallNoLogging{}, r), "AEGIS-GCP-069")
}

// --- 070: all protocols ---
func TestGCP070_AllProtocolsFires(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{
		"allow": blks(3, blk("protocol", ks("all", 4))),
	})
	mustFinding(t, runRule(firewallAllProtocols{}, r), "AEGIS-GCP-070")
}
func TestGCP070_SpecificProtocolQuiet(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": sl(3, "0.0.0.0/0"),
		"allow":         blks(3, blk("protocol", ks("tcp", 4))),
	})
	if len(runRule(firewallAllProtocols{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-070: expected 0 findings")
	}
}

// --- 071: egress all ---
func TestGCP071_EgressAllFires(t *testing.T) {
	rr := res("google_compute_firewall", "f", map[string]ir.Value{
		"direction": ks("EGRESS", 3), "destination_ranges": sl(4, "0.0.0.0/0"),
	})
	mustFinding(t, runRule(firewallEgressAll{}, rr), "AEGIS-GCP-071")
}

// --- 072: owner binding ---
func TestGCP072_OwnerFires(t *testing.T) {
	r := res("google_project_iam_binding", "b", map[string]ir.Value{"role": ks("roles/owner", 3)})
	mustFinding(t, runRule(iamOwnerBinding{}, r), "AEGIS-GCP-072")
}
func TestGCP072_ViewerQuiet(t *testing.T) {
	r := res("google_project_iam_binding", "b", map[string]ir.Value{"role": ks("roles/viewer", 3)})
	if len(runRule(iamOwnerBinding{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-072: expected 0 findings")
	}
}

// --- 073: editor binding ---
func TestGCP073_EditorFires(t *testing.T) {
	r := res("google_project_iam_binding", "b", map[string]ir.Value{"role": ks("roles/editor", 3)})
	mustFinding(t, runRule(iamEditorBinding{}, r), "AEGIS-GCP-073")
}
func TestGCP073_ViewerQuiet(t *testing.T) {
	r := res("google_project_iam_binding", "b", map[string]ir.Value{"role": ks("roles/viewer", 3)})
	if len(runRule(iamEditorBinding{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-073: expected 0 findings")
	}
}

// --- 074: viewer to user ---
func TestGCP074_ViewerUserFires(t *testing.T) {
	r := res("google_project_iam_member", "m", map[string]ir.Value{
		"role": ks("roles/viewer", 3), "member": ks("user:a@b.com", 4),
	})
	mustFinding(t, runRule(iamViewerUser{}, r), "AEGIS-GCP-074")
}

// --- 075: SA key ---
func TestGCP075_SAKeyFires(t *testing.T) {
	r := res("google_service_account_key", "k", map[string]ir.Value{})
	mustFinding(t, runRule(saUserManagedKey{}, r), "AEGIS-GCP-075")
}
func TestGCP075_NoKeyQuiet(t *testing.T) {
	// Presence-based rule: the secure configuration is the absence of a
	// user-managed key resource, so any other resource type must stay quiet.
	r := res("google_service_account", "s", map[string]ir.Value{})
	if len(runRule(saUserManagedKey{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-075: expected 0 findings without a user-managed key")
	}
}

// --- 076: IAM public ---
func TestGCP076_PublicFires(t *testing.T) {
	r := res("google_project_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/viewer", 3), "members": sl(4, "allUsers"),
	})
	mustFinding(t, runRule(iamMemberPublic{}, r), "AEGIS-GCP-076")
}
func TestGCP076_PrivateQuiet(t *testing.T) {
	r := res("google_project_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/viewer", 3), "members": sl(4, "user:a@b.com"),
	})
	if len(runRule(iamMemberPublic{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-076: expected 0 findings")
	}
}

// --- 077: SA IAM public ---
func TestGCP077_SAPublicFires(t *testing.T) {
	r := res("google_service_account_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/iam.serviceAccountUser", 3), "members": sl(4, "allUsers"),
	})
	mustFinding(t, runRule(saIAMBindingPublic{}, r), "AEGIS-GCP-077")
}
func TestGCP077_SAPrivateQuiet(t *testing.T) {
	r := res("google_service_account_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/iam.serviceAccountUser", 3), "members": sl(4, "user:a@b.com"),
	})
	if len(runRule(saIAMBindingPublic{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-077: expected 0 findings")
	}
}

// --- 078: custom role wildcard ---
func TestGCP078_WildcardFires(t *testing.T) {
	r := res("google_project_iam_custom_role", "r", map[string]ir.Value{
		"permissions": sl(3, "compute.instances.*"),
	})
	mustFinding(t, runRule(customRoleBroad{}, r), "AEGIS-GCP-078")
}

// --- 079: no audit config ---
func TestGCP079_NoAuditConfigFires(t *testing.T) {
	r := res("google_project_iam_policy", "p", map[string]ir.Value{})
	mustFinding(t, runRule(iamNoAuditConfig{}, r), "AEGIS-GCP-079")
}

// --- 080: workload pool no OIDC ---
func TestGCP080_NoOIDCFires(t *testing.T) {
	r := res("google_iam_workload_identity_pool_provider", "p", map[string]ir.Value{})
	mustFinding(t, runRule(workloadPoolNoOIDC{}, r), "AEGIS-GCP-080")
}

// --- 081: KMS long rotation ---
func TestGCP081_LongRotationFires(t *testing.T) {
	r := res("google_kms_crypto_key", "k", map[string]ir.Value{"rotation_period": ks("31536000s", 3)})
	mustFinding(t, runRule(kmsLongRotation{}, r), "AEGIS-GCP-081")
}
func TestGCP081_ShortRotationQuiet(t *testing.T) {
	r := res("google_kms_crypto_key", "k", map[string]ir.Value{"rotation_period": ks("7776000s", 3)})
	if len(runRule(kmsLongRotation{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 082: KMS public ---
func TestGCP082_KMSPublicFires(t *testing.T) {
	r := res("google_kms_crypto_key_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/cloudkms.cryptoKeyEncrypter", 3), "members": sl(4, "allUsers"),
	})
	mustFinding(t, runRule(kmsIAMPublic{}, r), "AEGIS-GCP-082")
}
func TestGCP082_KMSPrivateQuiet(t *testing.T) {
	r := res("google_kms_crypto_key_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/cloudkms.cryptoKeyEncrypter", 3), "members": sl(4, "user:a@b.com"),
	})
	if len(runRule(kmsIAMPublic{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-082: expected 0 findings")
	}
}

// --- 083: KMS admin to user ---
func TestGCP083_KMSAdminUserFires(t *testing.T) {
	r := res("google_kms_crypto_key_iam_member", "m", map[string]ir.Value{
		"role": ks("roles/cloudkms.admin", 3), "member": ks("user:a@b.com", 4),
	})
	mustFinding(t, runRule(kmsAdminToUser{}, r), "AEGIS-GCP-083")
}
func TestGCP083_KMSGroupQuiet(t *testing.T) {
	r := res("google_kms_crypto_key_iam_member", "m", map[string]ir.Value{
		"role": ks("roles/cloudkms.admin", 3), "member": ks("group:admins@example.com", 4),
	})
	if len(runRule(kmsAdminToUser{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-083: expected 0 findings")
	}
}

// --- 084: KMS weak algo ---
func TestGCP084_WeakAlgoFires(t *testing.T) {
	r := res("google_kms_crypto_key", "k", map[string]ir.Value{
		"version_template": blks(3, blk("algorithm", ks("RSA_DECRYPT_OAEP_1024_SHA1", 4))),
	})
	mustFinding(t, runRule(kmsWeakAlgorithm{}, r), "AEGIS-GCP-084")
}

// --- 085: sink unique writer ---
func TestGCP085_NoUniqueWriterFires(t *testing.T) {
	r := res("google_logging_project_sink", "s", map[string]ir.Value{"unique_writer_identity": kv(false, 3)})
	mustFinding(t, runRule(sinkNoUniqueWriter{}, r), "AEGIS-GCP-085")
}

// --- 086: audit exempt public ---
func TestGCP086_ExemptPublicFires(t *testing.T) {
	r := res("google_project_iam_policy", "p", map[string]ir.Value{
		"audit_config": blks(3, blk("audit_log_configs",
			blks(4, blk("log_type", ks("DATA_READ", 5), "exempted_members", sl(5, "allUsers"))))),
	})
	mustFinding(t, runRule(auditExemptAllUsers{}, r), "AEGIS-GCP-086")
}
func TestGCP086_PrivateExemptQuiet(t *testing.T) {
	r := res("google_project_iam_policy", "p", map[string]ir.Value{
		"audit_config": blks(3, blk("audit_log_configs",
			blks(4, blk("log_type", ks("DATA_READ", 5), "exempted_members", sl(5, "user:a@b.com"))))),
	})
	if len(runRule(auditExemptAllUsers{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-086: expected 0 findings")
	}
}

// --- 087: no DATA_READ ---
func TestGCP087_NoDataReadFires(t *testing.T) {
	r := res("google_project_iam_policy", "p", map[string]ir.Value{
		"audit_config": blks(3, blk("audit_log_configs",
			blks(4, blk("log_type", ks("ADMIN_READ", 5))))),
	})
	mustFinding(t, runRule(auditNoDataRead{}, r), "AEGIS-GCP-087")
}

// --- 088: auto network ---
func TestGCP088_AutoNetworkFires(t *testing.T) {
	r := res("google_project", "p", map[string]ir.Value{})
	mustFinding(t, runRule(projectAutoNetwork{}, r), "AEGIS-GCP-088")
}
func TestGCP088_NoAutoNetworkQuiet(t *testing.T) {
	r := res("google_project", "p", map[string]ir.Value{"auto_create_network": kv(false, 3)})
	if len(runRule(projectAutoNetwork{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 089: project OS login ---
func TestGCP089_NoOSLoginFires(t *testing.T) {
	r := res("google_compute_project_metadata", "m", map[string]ir.Value{
		"metadata": ir.Value{Raw: map[string]ir.Value{"enable-oslogin": ks("FALSE", 4)}, Known: true, Span: spanAt(3)},
	})
	mustFinding(t, runRule(projectMetadataNoOSLogin{}, r), "AEGIS-GCP-089")
}

// --- 090: sink filter ---
func TestGCP090_NoFilterFires(t *testing.T) {
	r := res("google_logging_project_sink", "s", map[string]ir.Value{})
	mustFinding(t, runRule(logSinkNoFilter{}, r), "AEGIS-GCP-090")
}

// --- 091: DNS policy logging ---
func TestGCP091_NoDNSLoggingFires(t *testing.T) {
	r := res("google_dns_policy", "p", map[string]ir.Value{})
	mustFinding(t, runRule(dnsPolicyNoLogging{}, r), "AEGIS-GCP-091")
}

// --- 092: DNS wildcard ---
func TestGCP092_WildcardFires(t *testing.T) {
	r := res("google_dns_record_set", "r", map[string]ir.Value{"name": ks("*.example.com.", 3)})
	mustFinding(t, runRule(dnsWildcardRecord{}, r), "AEGIS-GCP-092")
}

// --- 093: weak DNSSEC ---
func TestGCP093_WeakDNSSECFires(t *testing.T) {
	r := res("google_dns_managed_zone", "z", map[string]ir.Value{
		"dnssec_config": blks(3, blk("default_key_specs",
			blks(4, blk("algorithm", ks("rsasha1", 5))))),
	})
	mustFinding(t, runRule(dnsWeakDNSSEC{}, r), "AEGIS-GCP-093")
}

// --- 094: pubsub retention ---
func TestGCP094_NoRetentionFires(t *testing.T) {
	r := res("google_pubsub_topic", "t", map[string]ir.Value{})
	mustFinding(t, runRule(pubsubNoRetention{}, r), "AEGIS-GCP-094")
}

// --- 095: pubsub dead letter ---
func TestGCP095_NoDeadLetterFires(t *testing.T) {
	r := res("google_pubsub_subscription", "s", map[string]ir.Value{})
	mustFinding(t, runRule(pubsubNoDeadLetter{}, r), "AEGIS-GCP-095")
}

// --- 096: pubsub public ---
func TestGCP096_PubsubPublicFires(t *testing.T) {
	r := res("google_pubsub_topic_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/pubsub.publisher", 3), "members": sl(4, "allUsers"),
	})
	mustFinding(t, runRule(pubsubTopicPublic{}, r), "AEGIS-GCP-096")
}
func TestGCP096_PrivateQuiet(t *testing.T) {
	r := res("google_pubsub_topic_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/pubsub.publisher", 3), "members": sl(4, "user:a@b.com"),
	})
	if len(runRule(pubsubTopicPublic{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-096: expected 0 findings")
	}
}

// --- 097: cloud run public ---
func TestGCP097_RunPublicFires(t *testing.T) {
	r := res("google_cloud_run_service_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/run.invoker", 3), "members": sl(4, "allUsers"),
	})
	mustFinding(t, runRule(cloudRunPublic{}, r), "AEGIS-GCP-097")
}
func TestGCP097_PrivateQuiet(t *testing.T) {
	r := res("google_cloud_run_service_iam_binding", "b", map[string]ir.Value{
		"role": ks("roles/run.invoker", 3), "members": sl(4, "user:a@b.com"),
	})
	if len(runRule(cloudRunPublic{}, r)) != 0 {
		t.Fatal("AEGIS-GCP-097: expected 0 findings")
	}
}

// --- 098: function max instances ---
func TestGCP098_NoMaxInstancesFires(t *testing.T) {
	r := res("google_cloudfunctions_function", "f", map[string]ir.Value{})
	mustFinding(t, runRule(functionNoMaxInstances{}, r), "AEGIS-GCP-098")
}

// --- 099: cloud run default SA ---
func TestGCP099_RunDefaultSAFires(t *testing.T) {
	r := res("google_cloud_run_service", "s", map[string]ir.Value{
		"template": blks(3, blk("spec", blks(4, blk()))),
	})
	mustFinding(t, runRule(cloudRunDefaultSA{}, r), "AEGIS-GCP-099")
}

// --- 100: function public source ---
func TestGCP100_PublicSourceFires(t *testing.T) {
	r := res("google_cloudfunctions_function", "f", map[string]ir.Value{
		"source_archive_bucket": ks("my-public-functions", 3),
	})
	mustFinding(t, runRule(functionPublicSource{}, r), "AEGIS-GCP-100")
}
func TestGCP100_PrivateSourceQuiet(t *testing.T) {
	r := res("google_cloudfunctions_function", "f", map[string]ir.Value{
		"source_archive_bucket": ks("my-private-functions", 3),
	})
	if len(runRule(functionPublicSource{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// Unknown-value contract spot checks for new rules
func TestGCP3_UnknownQuiet(t *testing.T) {
	cases := []struct {
		rule ir.Rule
		res  ir.Resource
	}{
		{bucketNoCMEK{}, res("google_storage_bucket", "b", map[string]ir.Value{"encryption": ku(3)})},
		{bqPublicAccess{}, res("google_bigquery_dataset", "d", map[string]ir.Value{"access": ku(3)})},
		{firewallOpenRDP{}, res("google_compute_firewall", "f", map[string]ir.Value{
			"source_ranges": ku(3),
			"allow":         blks(4, blk("protocol", ks("tcp", 5), "ports", sl(5, "3389"))),
		})},
		{iamOwnerBinding{}, res("google_project_iam_binding", "b", map[string]ir.Value{"role": ku(3)})},
	}
	for _, c := range cases {
		if len(runRule(c.rule, c.res)) != 0 {
			t.Fatalf("rule %s: expected 0 findings for unknown", c.rule.ID())
		}
	}
}

// Verify all 75 rules are registered in ID order (063 removed: exact duplicate of 018)
func TestGCP3_AllRegistered(t *testing.T) {
	rules := GCP3Rules()
	if len(rules) != 74 {
		t.Fatalf("expected 74 rules, got %d", len(rules))
	}
	wantIDs := []int{}
	for n := 25; n <= 100; n++ {
		if n == 63 { // removed: exact duplicate of 018
			continue
		}
		if n == 48 { // removed in Sprint 2: strict subset of 109
			continue
		}
		wantIDs = append(wantIDs, n)
	}
	for i, r := range rules {
		want := wantIDs[i]
		var got int
		_, err := scanID(r.ID(), &got)
		if err != nil || got != want {
			t.Fatalf("rule %d: want AEGIS-GCP-%03d, got %s", i, want, r.ID())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %s missing title/description", r.ID())
		}
	}
}

func scanID(id string, out *int) (bool, error) {
	var n int
	_, err := fmt.Sscanf(id, "AEGIS-GCP-%d", &n)
	if err != nil {
		return false, err
	}
	*out = n
	return true, nil
}

// --- 046: engine gating — log_disconnections is PostgreSQL-only ---
func TestGCP046_MySQLQuiet(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"database_version": ks("MYSQL_5_7", 2),
		"settings":         blks(3, blk()),
	})
	if len(runRule(sqlNoLogDisconnections{}, r)) != 0 {
		t.Fatal("GCP-046 must not fire on MySQL")
	}
}

func TestGCP046_PostgresFires(t *testing.T) {
	r := res("google_sql_database_instance", "db", map[string]ir.Value{
		"database_version": ks("POSTGRES_15", 2),
		"settings":         blks(3, blk()),
	})
	mustFinding(t, runRule(sqlNoLogDisconnections{}, r), "AEGIS-GCP-046")
}
