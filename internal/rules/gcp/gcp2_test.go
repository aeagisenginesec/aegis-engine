package gcp

import (
	"testing"

	"aegis/internal/ir"
)

func TestGCP005_NoUniformAccessFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"uniform_bucket_level_access": kv(false, 3)})
	mustFinding(t, runRule(bucketNoUniformAccess{}, r), "AEGIS-GCP-005")
}

func TestGCP005_UniformQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"uniform_bucket_level_access": kv(true, 3)})
	if len(runRule(bucketNoUniformAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP005_UnknownQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"uniform_bucket_level_access": ku(3)})
	if len(runRule(bucketNoUniformAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP006_NoCMEKFires(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{})
	mustFinding(t, runRule(bigQueryNoCMEK{}, r), "AEGIS-GCP-006")
}

func TestGCP006_CMEKQuiet(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{
		"default_encryption_configuration": blks(3, blk("kms_key_name", ks("k", 4))),
	})
	if len(runRule(bigQueryNoCMEK{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP006_UnknownQuiet(t *testing.T) {
	r := res("google_bigquery_dataset", "d", map[string]ir.Value{"default_encryption_configuration": ku(3)})
	if len(runRule(bigQueryNoCMEK{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

// ipConfig builds a settings block containing one ip_configuration block
// from key/value pairs.
func ipConfig(pairs ...any) ir.Value {
	inner := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		inner[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	ipc := ir.Value{
		Raw:   []ir.Value{{Raw: inner, Known: true, Span: spanAt(5)}},
		Known: true, Span: spanAt(4),
	}
	return blks(3, blk("ip_configuration", ipc))
}

func TestGCP007_PublicIPFires(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{
		"settings": ipConfig("ipv4_enabled", kv(true, 5)),
	})
	mustFinding(t, runRule(sqlPublicIP{}, r), "AEGIS-GCP-007")
}

func TestGCP007_PrivateQuiet(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{
		"settings": ipConfig("ipv4_enabled", kv(false, 5)),
	})
	if len(runRule(sqlPublicIP{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP007_UnknownQuiet(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{
		"settings": ipConfig("ipv4_enabled", ku(5)),
	})
	if len(runRule(sqlPublicIP{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP008_NoSSLFires(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{
		"settings": ipConfig("require_ssl", kv(false, 5)),
	})
	mustFinding(t, runRule(sqlNoSSL{}, r), "AEGIS-GCP-008")
}

func TestGCP008_SSLQuiet(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{
		"settings": ipConfig("require_ssl", kv(true, 5)),
	})
	if len(runRule(sqlNoSSL{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP008_UnknownQuiet(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{
		"settings": ipConfig("require_ssl", ku(5)),
	})
	if len(runRule(sqlNoSSL{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP009_LegacyABACFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"enable_legacy_abac": kv(true, 3)})
	mustFinding(t, runRule(gkeLegacyABAC{}, r), "AEGIS-GCP-009")
}

func TestGCP009_ABACOffQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"enable_legacy_abac": kv(false, 3)})
	if len(runRule(gkeLegacyABAC{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP009_UnknownQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"enable_legacy_abac": ku(3)})
	if len(runRule(gkeLegacyABAC{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP010_NoNetworkPolicyFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeNoNetworkPolicy{}, r), "AEGIS-GCP-010")
}

func TestGCP010_DisabledFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"network_policy": blks(3, blk("enabled", kv(false, 4))),
	})
	mustFinding(t, runRule(gkeNoNetworkPolicy{}, r), "AEGIS-GCP-010")
}

func TestGCP010_EnabledQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"network_policy": blks(3, blk("enabled", kv(true, 4))),
	})
	if len(runRule(gkeNoNetworkPolicy{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP011_NoPrivateClusterFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeNoPrivateCluster{}, r), "AEGIS-GCP-011")
}

func TestGCP011_PrivateQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"private_cluster_config": blks(3, blk("enable_private_nodes", kv(true, 4))),
	})
	if len(runRule(gkeNoPrivateCluster{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP011_UnknownQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"private_cluster_config": ku(3)})
	if len(runRule(gkeNoPrivateCluster{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP012_NoRotationFires(t *testing.T) {
	r := res("google_kms_crypto_key", "k", map[string]ir.Value{})
	mustFinding(t, runRule(kmsNoRotation{}, r), "AEGIS-GCP-012")
}

func TestGCP012_RotationQuiet(t *testing.T) {
	r := res("google_kms_crypto_key", "k", map[string]ir.Value{"rotation_period": ks("7776000s", 3)})
	if len(runRule(kmsNoRotation{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP012_UnknownQuiet(t *testing.T) {
	r := res("google_kms_crypto_key", "k", map[string]ir.Value{"rotation_period": ku(3)})
	if len(runRule(kmsNoRotation{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP013_IngressAllFires(t *testing.T) {
	for _, typ := range []string{"google_cloudfunctions_function", "google_cloudfunctions2_function"} {
		r := res(typ, "f", map[string]ir.Value{"ingress_settings": ks("ALLOW_ALL", 3)})
		mustFinding(t, runRule(functionIngressAll{}, r), "AEGIS-GCP-013")
	}
}

func TestGCP013_InternalQuiet(t *testing.T) {
	r := res("google_cloudfunctions2_function", "f", map[string]ir.Value{"ingress_settings": ks("ALLOW_INTERNAL_ONLY", 3)})
	if len(runRule(functionIngressAll{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP013_UnknownQuiet(t *testing.T) {
	r := res("google_cloudfunctions_function", "f", map[string]ir.Value{"ingress_settings": ku(3)})
	if len(runRule(functionIngressAll{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func openSSHFirewall() ir.Resource {
	return res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": strList(3, "0.0.0.0/0"),
		"allow":         blks(3, blk("protocol", ks("tcp", 4), "ports", strList(4, "22"))),
	})
}

func TestGCP014_OpenSSHFires(t *testing.T) {
	mustFinding(t, runRule(firewallOpenSSH{}, openSSHFirewall()), "AEGIS-GCP-014")
}

func TestGCP014_RestrictedQuiet(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": strList(3, "10.0.0.0/8"),
		"allow":         blks(3, blk("protocol", ks("tcp", 4), "ports", strList(4, "22"))),
	})
	if len(runRule(firewallOpenSSH{}, r)) != 0 {
		t.Fatal("expected 0 findings for restricted source")
	}
}

func TestGCP014_NoSSHQuiet(t *testing.T) {
	r := res("google_compute_firewall", "f", map[string]ir.Value{
		"source_ranges": strList(3, "0.0.0.0/0"),
		"allow":         blks(3, blk("protocol", ks("tcp", 4), "ports", strList(4, "443"))),
	})
	if len(runRule(firewallOpenSSH{}, r)) != 0 {
		t.Fatal("expected 0 findings for non-SSH port")
	}
}

func TestGCP015_NoArmorFires(t *testing.T) {
	r := res("google_compute_backend_service", "b", map[string]ir.Value{})
	mustFinding(t, runRule(backendNoCloudArmor{}, r), "AEGIS-GCP-015")
}

func TestGCP015_ArmorQuiet(t *testing.T) {
	r := res("google_compute_backend_service", "b", map[string]ir.Value{"security_policy": ks("policy-id", 3)})
	if len(runRule(backendNoCloudArmor{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP015_UnknownQuiet(t *testing.T) {
	r := res("google_compute_backend_service", "b", map[string]ir.Value{"security_policy": ku(3)})
	if len(runRule(backendNoCloudArmor{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP016_NoVersioningFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{})
	mustFinding(t, runRule(bucketNoVersioning{}, r), "AEGIS-GCP-016")
}

func TestGCP016_VersioningQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{
		"versioning": blks(3, blk("enabled", kv(true, 4))),
	})
	if len(runRule(bucketNoVersioning{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP016_UnknownQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{
		"versioning": blks(3, blk("enabled", ku(4))),
	})
	if len(runRule(bucketNoVersioning{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

// nicWithAccess builds a network_interface block list containing one NIC;
// when withAccess is true the NIC has an (empty) access_config block.
func nicWithAccess(withAccess bool) ir.Value {
	nic := map[string]ir.Value{}
	if withAccess {
		nic["access_config"] = ir.Value{
			Raw:   []ir.Value{{Raw: map[string]ir.Value{}, Known: true, Span: spanAt(4)}},
			Known: true, Span: spanAt(4),
		}
	}
	return blks(3, nic)
}

func TestGCP017_PublicIPFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"network_interface": nicWithAccess(true),
	})
	mustFinding(t, runRule(instancePublicIP{}, r), "AEGIS-GCP-017")
}

func TestGCP017_NoAccessConfigQuiet(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"network_interface": nicWithAccess(false),
	})
	if len(runRule(instancePublicIP{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP017_UnknownQuiet(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{"network_interface": ku(3)})
	if len(runRule(instancePublicIP{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP018_BroadScopeFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"service_account": blks(3, blk("scopes", strList(4, "https://www.googleapis.com/auth/cloud-platform"))),
	})
	mustFinding(t, runRule(instanceBroadScope{}, r), "AEGIS-GCP-018")
}

func TestGCP018_NarrowScopeQuiet(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"service_account": blks(3, blk("scopes", strList(4, "https://www.googleapis.com/auth/logging.write"))),
	})
	if len(runRule(instanceBroadScope{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP018_UnknownQuiet(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{"service_account": ku(3)})
	if len(runRule(instanceBroadScope{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP019_NoDeletionProtectionFires(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{"deletion_protection": kv(false, 3)})
	mustFinding(t, runRule(sqlNoDeletionProtection{}, r), "AEGIS-GCP-019")
}

func TestGCP019_AbsentFires(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{})
	mustFinding(t, runRule(sqlNoDeletionProtection{}, r), "AEGIS-GCP-019")
}

func TestGCP019_ProtectedQuiet(t *testing.T) {
	r := res("google_sql_database_instance", "s", map[string]ir.Value{"deletion_protection": kv(true, 3)})
	if len(runRule(sqlNoDeletionProtection{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP020_NoCMEKFires(t *testing.T) {
	r := res("google_pubsub_topic", "t", map[string]ir.Value{})
	mustFinding(t, runRule(pubsubNoCMEK{}, r), "AEGIS-GCP-020")
}

func TestGCP020_CMEKQuiet(t *testing.T) {
	r := res("google_pubsub_topic", "t", map[string]ir.Value{"kms_key_name": ks("k", 3)})
	if len(runRule(pubsubNoCMEK{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP020_UnknownQuiet(t *testing.T) {
	r := res("google_pubsub_topic", "t", map[string]ir.Value{"kms_key_name": ku(3)})
	if len(runRule(pubsubNoCMEK{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP021_NoLoggingFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"logging_service": ks("none", 3)})
	mustFinding(t, runRule(gkeNoLogging{}, r), "AEGIS-GCP-021")
}

func TestGCP021_LoggingQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"logging_service": ks("logging.googleapis.com/kubernetes", 3)})
	if len(runRule(gkeNoLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP021_UnknownQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"logging_service": ku(3)})
	if len(runRule(gkeNoLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP022_NoRotationFires(t *testing.T) {
	r := res("google_secret_manager_secret", "s", map[string]ir.Value{})
	mustFinding(t, runRule(secretNoRotation{}, r), "AEGIS-GCP-022")
}

func TestGCP022_RotationQuiet(t *testing.T) {
	r := res("google_secret_manager_secret", "s", map[string]ir.Value{
		"rotation": blks(3, blk("rotation_period", ks("7776000s", 4))),
	})
	if len(runRule(secretNoRotation{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP022_UnknownQuiet(t *testing.T) {
	r := res("google_secret_manager_secret", "s", map[string]ir.Value{"rotation": ku(3)})
	if len(runRule(secretNoRotation{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP023_NoPrivateAccessFires(t *testing.T) {
	r := res("google_compute_subnetwork", "s", map[string]ir.Value{"private_ip_google_access": kv(false, 3)})
	mustFinding(t, runRule(subnetNoPrivateAccess{}, r), "AEGIS-GCP-023")
}

func TestGCP023_PrivateAccessQuiet(t *testing.T) {
	r := res("google_compute_subnetwork", "s", map[string]ir.Value{"private_ip_google_access": kv(true, 3)})
	if len(runRule(subnetNoPrivateAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP023_UnknownQuiet(t *testing.T) {
	r := res("google_compute_subnetwork", "s", map[string]ir.Value{"private_ip_google_access": ku(3)})
	if len(runRule(subnetNoPrivateAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP024_NoDNSSECFires(t *testing.T) {
	r := res("google_dns_managed_zone", "z", map[string]ir.Value{})
	mustFinding(t, runRule(dnsNoDNSSEC{}, r), "AEGIS-GCP-024")
}

func TestGCP024_DNSSECQuiet(t *testing.T) {
	r := res("google_dns_managed_zone", "z", map[string]ir.Value{
		"dnssec_config": blks(3, blk()),
	})
	if len(runRule(dnsNoDNSSEC{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestGCP024_UnknownQuiet(t *testing.T) {
	r := res("google_dns_managed_zone", "z", map[string]ir.Value{"dnssec_config": ku(3)})
	if len(runRule(dnsNoDNSSEC{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestGCP2Rules_IDOrder(t *testing.T) {
	rules := GCP2Rules()
	want := []string{
		"AEGIS-GCP-005", "AEGIS-GCP-006", "AEGIS-GCP-007", "AEGIS-GCP-008",
		"AEGIS-GCP-009", "AEGIS-GCP-010", "AEGIS-GCP-011", "AEGIS-GCP-012",
		"AEGIS-GCP-013", "AEGIS-GCP-014", "AEGIS-GCP-015", "AEGIS-GCP-016",
		"AEGIS-GCP-017", "AEGIS-GCP-018", "AEGIS-GCP-019", "AEGIS-GCP-020",
		"AEGIS-GCP-021", "AEGIS-GCP-022", "AEGIS-GCP-023", "AEGIS-GCP-024",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("rule %d: want %s, got %s", i, w, rules[i].ID())
		}
		if rules[i].Title() == "" || rules[i].Description() == "" {
			t.Fatalf("rule %s missing title/description", w)
		}
	}
}
