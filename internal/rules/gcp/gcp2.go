// Package gcp — extended rule pack (AEGIS-GCP-005..024).
//
// Same unknown-value contract as the base pack: a present-but-unresolved
// attribute yields NO finding. Absent attributes are evaluated against the
// documented insecure default per rule; rules that fire on absence say so
// explicitly. Rules never panic on unexpected shapes.
package gcp

import (
	"strings"

	"aegis/internal/ir"
)

// GCP2Rules returns the extended GCP rules in ID order.
func GCP2Rules() []ir.Rule {
	return []ir.Rule{
		bucketNoUniformAccess{},   // AEGIS-GCP-005
		bigQueryNoCMEK{},          // AEGIS-GCP-006
		sqlPublicIP{},             // AEGIS-GCP-007
		sqlNoSSL{},                // AEGIS-GCP-008
		gkeLegacyABAC{},           // AEGIS-GCP-009
		gkeNoNetworkPolicy{},      // AEGIS-GCP-010
		gkeNoPrivateCluster{},     // AEGIS-GCP-011
		kmsNoRotation{},           // AEGIS-GCP-012
		functionIngressAll{},      // AEGIS-GCP-013
		firewallOpenSSH{},         // AEGIS-GCP-014
		backendNoCloudArmor{},     // AEGIS-GCP-015
		bucketNoVersioning{},      // AEGIS-GCP-016
		instancePublicIP{},        // AEGIS-GCP-017
		instanceBroadScope{},      // AEGIS-GCP-018
		sqlNoDeletionProtection{}, // AEGIS-GCP-019
		pubsubNoCMEK{},            // AEGIS-GCP-020
		gkeNoLogging{},            // AEGIS-GCP-021
		secretNoRotation{},        // AEGIS-GCP-022
		subnetNoPrivateAccess{},   // AEGIS-GCP-023
		dnsNoDNSSEC{},             // AEGIS-GCP-024
	}
}

// getBool classifies a boolean attribute into a tri-state.
func getBool(r ir.Resource, name string) (val bool, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-005: GCS bucket without uniform bucket-level access
// ---------------------------------------------------------------------------

type bucketNoUniformAccess struct{}

func (bucketNoUniformAccess) ID() string { return "AEGIS-GCP-005" }
func (bucketNoUniformAccess) Title() string {
	return "GCS bucket without uniform bucket-level access"
}
func (bucketNoUniformAccess) Description() string {
	return "google_storage_bucket with uniform_bucket_level_access = false " +
		"allows per-object ACLs, which can silently expose individual " +
		"objects. Enable uniform access to manage permissions via IAM only."
}
func (bucketNoUniformAccess) Severity() ir.Severity { return ir.SeverityHigh }

func (bucketNoUniformAccess) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket"
}

func (s bucketNoUniformAccess) Check(r ir.Resource) []ir.Finding {
	uni, span, present, known := getBool(r, "uniform_bucket_level_access")
	if !present {
		return []ir.Finding{mkFinding(s, r, "uniform_bucket_level_access", r.Span,
			"absent", "uniform_bucket_level_access = true")}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if uni {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "uniform_bucket_level_access", span,
		"false", "uniform_bucket_level_access = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-006: BigQuery dataset without customer-managed encryption
// ---------------------------------------------------------------------------

type bigQueryNoCMEK struct{}

func (bigQueryNoCMEK) ID() string { return "AEGIS-GCP-006" }
func (bigQueryNoCMEK) Title() string {
	return "BigQuery dataset without customer-managed encryption"
}
func (bigQueryNoCMEK) Description() string {
	return "google_bigquery_dataset with no default_encryption_configuration " +
		"block relies on Google-managed keys. Declare a CMEK via " +
		"default_encryption_configuration for key control and rotation."
}
func (bigQueryNoCMEK) Severity() ir.Severity { return ir.SeverityHigh }

func (bigQueryNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_bigquery_dataset"
}

func (s bigQueryNoCMEK) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "default_encryption_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil // CMEK configured
	}
	// Absent: no customer-managed encryption. Documented insecure default.
	return []ir.Finding{mkFinding(s, r, "default_encryption_configuration", r.Span,
		"absent", "default_encryption_configuration { kms_key_name = ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-007: Cloud SQL instance with public IP
// ---------------------------------------------------------------------------

type sqlPublicIP struct{}

func (sqlPublicIP) ID() string { return "AEGIS-GCP-007" }
func (sqlPublicIP) Title() string {
	return "Cloud SQL instance with public IP"
}
func (sqlPublicIP) Description() string {
	return "google_sql_database_instance with " +
		"settings.ip_configuration.ipv4_enabled = true exposes the database " +
		"to the internet. Use private IP with VPC peering instead."
}
func (sqlPublicIP) Severity() ir.Severity { return ir.SeverityHigh }

func (sqlPublicIP) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

// ipConfigBlocks returns the settings.ip_configuration blocks.
func ipConfigBlocks(r ir.Resource) []map[string]ir.Value {
	var out []map[string]ir.Value
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		out = append(out, blockList(st, "ip_configuration")...)
	}
	return out
}

func (s sqlPublicIP) Check(r ir.Resource) []ir.Finding {
	for _, ipc := range ipConfigBlocks(r) {
		v4, span, present, known := blockBool(ipc, "ipv4_enabled")
		if !present || !known {
			continue // unresolved: cannot decide for this block
		}
		if v4 {
			return []ir.Finding{mkFinding(s, r,
				"settings.ip_configuration.ipv4_enabled", span,
				"true", "ipv4_enabled = false (private IP only)")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-008: Cloud SQL instance without SSL enforcement
// ---------------------------------------------------------------------------

type sqlNoSSL struct{}

func (sqlNoSSL) ID() string { return "AEGIS-GCP-008" }
func (sqlNoSSL) Title() string {
	return "Cloud SQL instance without SSL enforcement"
}
func (sqlNoSSL) Description() string {
	return "google_sql_database_instance with " +
		"settings.ip_configuration.require_ssl = false accepts plaintext " +
		"database connections."
}
func (sqlNoSSL) Severity() ir.Severity { return ir.SeverityHigh }

func (sqlNoSSL) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlNoSSL) Check(r ir.Resource) []ir.Finding {
	for _, ipc := range ipConfigBlocks(r) {
		req, span, present, known := blockBool(ipc, "require_ssl")
		if !present || !known {
			continue // unresolved: cannot decide for this block
		}
		if !req {
			return []ir.Finding{mkFinding(s, r,
				"settings.ip_configuration.require_ssl", span,
				"false", "require_ssl = true")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-009: GKE cluster with legacy ABAC enabled
// ---------------------------------------------------------------------------

type gkeLegacyABAC struct{}

func (gkeLegacyABAC) ID() string { return "AEGIS-GCP-009" }
func (gkeLegacyABAC) Title() string {
	return "GKE cluster with legacy ABAC enabled"
}
func (gkeLegacyABAC) Description() string {
	return "google_container_cluster with enable_legacy_abac = true grants " +
		"broad, coarse-grained API access. Use RBAC instead."
}
func (gkeLegacyABAC) Severity() ir.Severity { return ir.SeverityHigh }

func (gkeLegacyABAC) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeLegacyABAC) Check(r ir.Resource) []ir.Finding {
	abac, span, present, known := getBool(r, "enable_legacy_abac")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !abac {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "enable_legacy_abac", span,
		"true", "enable_legacy_abac = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-010: GKE cluster without network policy
// ---------------------------------------------------------------------------

type gkeNoNetworkPolicy struct{}

func (gkeNoNetworkPolicy) ID() string { return "AEGIS-GCP-010" }
func (gkeNoNetworkPolicy) Title() string {
	return "GKE cluster without network policy"
}
func (gkeNoNetworkPolicy) Description() string {
	return "google_container_cluster with no network_policy block, or with " +
		"network_policy disabled, allows unrestricted pod-to-pod traffic."
}
func (gkeNoNetworkPolicy) Severity() ir.Severity { return ir.SeverityHigh }

func (gkeNoNetworkPolicy) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeNoNetworkPolicy) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "network_policy")
	if !present {
		// No network_policy block: disabled by default. Documented.
		return []ir.Finding{mkFinding(s, r, "network_policy", r.Span,
			"absent (disabled by default)", "network_policy { enabled = true }")}
	}
	if !known || len(blks) == 0 {
		return nil // unresolved: cannot decide
	}
	en, span, epresent, eknown := blockBool(blks[0], "enabled")
	if !epresent || !eknown {
		return nil // unresolved: cannot decide
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "network_policy.enabled", span,
			"false", "enabled = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-011: GKE cluster not private
// ---------------------------------------------------------------------------

type gkeNoPrivateCluster struct{}

func (gkeNoPrivateCluster) ID() string { return "AEGIS-GCP-011" }
func (gkeNoPrivateCluster) Title() string {
	return "GKE cluster not private"
}
func (gkeNoPrivateCluster) Description() string {
	return "google_container_cluster with no private_cluster_config block " +
		"assigns public IPs to nodes. Use private clusters so nodes have " +
		"internal IPs only."
}
func (gkeNoPrivateCluster) Severity() ir.Severity { return ir.SeverityHigh }

func (gkeNoPrivateCluster) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeNoPrivateCluster) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "private_cluster_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(blks) == 0 {
		// Absent: nodes get public IPs. Documented insecure default.
		return []ir.Finding{mkFinding(s, r, "private_cluster_config", r.Span,
			"absent", "private_cluster_config { enable_private_nodes = true }")}
	}
	en, span, p, k := blockBool(blks[0], "enable_private_nodes")
	if !p {
		return []ir.Finding{mkFinding(s, r, "private_cluster_config.enable_private_nodes",
			r.Span, "absent", "enable_private_nodes = true")}
	}
	if !k {
		return nil // unresolved: cannot decide
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "private_cluster_config.enable_private_nodes",
			span, "false", "true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-012: KMS crypto key without rotation
// ---------------------------------------------------------------------------

type kmsNoRotation struct{}

func (kmsNoRotation) ID() string { return "AEGIS-GCP-012" }
func (kmsNoRotation) Title() string {
	return "KMS crypto key without rotation"
}
func (kmsNoRotation) Description() string {
	return "google_kms_crypto_key with no rotation_period never rotates. " +
		"Set rotation_period (e.g. 7776000s for 90 days)."
}
func (kmsNoRotation) Severity() ir.Severity { return ir.SeverityHigh }

func (kmsNoRotation) AppliesTo(resType string) bool {
	return resType == "google_kms_crypto_key"
}

func (s kmsNoRotation) Check(r ir.Resource) []ir.Finding {
	rot, _, present, known := getString(r, "rotation_period")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(rot) != "" {
		return nil // rotation configured
	}
	// Absent: no rotation. Documented insecure default.
	return []ir.Finding{mkFinding(s, r, "rotation_period", r.Span,
		"absent", "rotation_period = \"7776000s\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-013: Cloud Function with public ingress
// ---------------------------------------------------------------------------

type functionIngressAll struct{}

func (functionIngressAll) ID() string { return "AEGIS-GCP-013" }
func (functionIngressAll) Title() string {
	return "Cloud Function with public ingress"
}
func (functionIngressAll) Description() string {
	return "Cloud Functions with ingress_settings = \"ALLOW_ALL\" accept " +
		"invocations from the public internet. Restrict to internal or " +
		"internal-and-GCLB traffic."
}
func (functionIngressAll) Severity() ir.Severity { return ir.SeverityHigh }

func (functionIngressAll) AppliesTo(resType string) bool {
	return resType == "google_cloudfunctions_function" ||
		resType == "google_cloudfunctions2_function"
}

func (s functionIngressAll) Check(r ir.Resource) []ir.Finding {
	ing, span, present, known := getString(r, "ingress_settings")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(ing), "ALLOW_ALL") {
		return []ir.Finding{mkFinding(s, r, "ingress_settings", span,
			ing, "ingress_settings = \"ALLOW_INTERNAL_ONLY\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-014: Firewall rule open to SSH from the internet
// ---------------------------------------------------------------------------

type firewallOpenSSH struct{}

func (firewallOpenSSH) ID() string { return "AEGIS-GCP-014" }
func (firewallOpenSSH) Title() string {
	return "Firewall rule open to SSH from the internet"
}
func (firewallOpenSSH) Description() string {
	return "A compute firewall with source_ranges 0.0.0.0/0 allowing " +
		"tcp:22 exposes SSH to the entire internet."
}
func (firewallOpenSSH) Severity() ir.Severity { return ir.SeverityMedium }

func (firewallOpenSSH) AppliesTo(resType string) bool {
	return resType == "google_compute_firewall"
}

// allowHasPort reports whether any allow block permits the given port on
// the given protocol (or all ports/protocols).
func allowHasPort(blks []map[string]ir.Value, protocol, port string) bool {
	for _, b := range blks {
		proto, _, ppresent, pknown := blockString(b, "protocol")
		if ppresent && pknown && !strings.EqualFold(strings.TrimSpace(proto), protocol) &&
			!strings.EqualFold(strings.TrimSpace(proto), "all") {
			continue
		}
		ports, _, ok := blockStringList(b, "ports")
		if !ok {
			// No ports list with a matching protocol means all ports.
			if !ppresent || (pknown && strings.EqualFold(strings.TrimSpace(proto), protocol)) {
				return true
			}
			continue
		}
		for _, p := range ports {
			if strings.TrimSpace(p) == port {
				return true
			}
		}
	}
	return false
}

// blockStringList extracts a string list from a block map.
// blockString extracts a single string from a block map (tri-state).
func blockString(m map[string]ir.Value, name string) (string, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

func blockStringList(m map[string]ir.Value, name string) ([]string, ir.Span, bool) {
	v, ok := m[name]
	if !ok || !v.Known {
		return nil, ir.Span{}, false
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, v.Span, false
		}
		out = append(out, s)
	}
	return out, v.Span, true
}

func (s firewallOpenSSH) Check(r ir.Resource) []ir.Finding {
	ranges, _, ok := getStringList(r, "source_ranges")
	if !ok {
		return nil
	}
	open := false
	for _, sr := range ranges {
		if strings.TrimSpace(sr) == "0.0.0.0/0" {
			open = true
			break
		}
	}
	if !open {
		return nil
	}
	blks, span, present, known := getBlocks(r, "allow")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	if allowHasPort(blks, "tcp", "22") {
		return []ir.Finding{mkFinding(s, r, "allow", span,
			"tcp:22 from 0.0.0.0/0", "restricted source_ranges for SSH")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-015: Backend service without Cloud Armor policy
// ---------------------------------------------------------------------------

type backendNoCloudArmor struct{}

func (backendNoCloudArmor) ID() string { return "AEGIS-GCP-015" }
func (backendNoCloudArmor) Title() string {
	return "Backend service without Cloud Armor policy"
}
func (backendNoCloudArmor) Description() string {
	return "google_compute_backend_service with no security_policy is not " +
		"protected by Cloud Armor. Attach a security policy for WAF and " +
		"DDoS protection."
}
func (backendNoCloudArmor) Severity() ir.Severity { return ir.SeverityMedium }

func (backendNoCloudArmor) AppliesTo(resType string) bool {
	return resType == "google_compute_backend_service"
}

func (s backendNoCloudArmor) Check(r ir.Resource) []ir.Finding {
	pol, _, present, known := getString(r, "security_policy")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(pol) != "" {
		return nil // policy attached
	}
	// Absent: no Cloud Armor policy. Documented insecure default.
	return []ir.Finding{mkFinding(s, r, "security_policy", r.Span,
		"absent", "security_policy = google_compute_security_policy.example.id")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-016: GCS bucket without versioning
// ---------------------------------------------------------------------------

type bucketNoVersioning struct{}

func (bucketNoVersioning) ID() string { return "AEGIS-GCP-016" }
func (bucketNoVersioning) Title() string {
	return "GCS bucket without versioning"
}
func (bucketNoVersioning) Description() string {
	return "google_storage_bucket with versioning disabled or absent loses " +
		"protection against accidental overwrites and deletions."
}
func (bucketNoVersioning) Severity() ir.Severity { return ir.SeverityHigh }

func (bucketNoVersioning) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket"
}

func (s bucketNoVersioning) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "versioning")
	if !present {
		return []ir.Finding{mkFinding(s, r, "versioning", r.Span,
			"absent (disabled by default)", "versioning { enabled = true }")}
	}
	if !known || len(blks) == 0 {
		return nil // unresolved: cannot decide
	}
	en, _, epresent, eknown := blockBool(blks[0], "enabled")
	if !epresent || !eknown {
		return nil // unresolved: cannot decide
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "versioning.enabled", span,
			"false", "enabled = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-017: Compute instance with public IP
// ---------------------------------------------------------------------------

type instancePublicIP struct{}

func (instancePublicIP) ID() string { return "AEGIS-GCP-017" }
func (instancePublicIP) Title() string {
	return "Compute instance with public IP"
}
func (instancePublicIP) Description() string {
	return "google_compute_instance with an access_config block on a " +
		"network_interface gets an ephemeral public IP. Remove access_config " +
		"for internal-only instances."
}
func (instancePublicIP) Severity() ir.Severity { return ir.SeverityHigh }

func (instancePublicIP) AppliesTo(resType string) bool {
	return resType == "google_compute_instance"
}

func (s instancePublicIP) Check(r ir.Resource) []ir.Finding {
	nics, _, present, known := getBlocks(r, "network_interface")
	if !present || !known {
		return nil
	}
	for _, nic := range nics {
		acs := blockList(nic, "access_config")
		if len(acs) > 0 {
			_, span, _, _ := blockString(acs[0], "nat_ip")
			return []ir.Finding{mkFinding(s, r,
				"network_interface.access_config", span,
				"present (public IP assigned)", "no access_config block")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-018: Compute instance with overly broad service-account scope
// ---------------------------------------------------------------------------

type instanceBroadScope struct{}

func (instanceBroadScope) ID() string { return "AEGIS-GCP-018" }
func (instanceBroadScope) Title() string {
	return "Compute instance with overly broad service-account scope"
}
func (instanceBroadScope) Description() string {
	return "google_compute_instance whose service_account scopes include " +
		"cloud-platform grants the VM full API access. Scope down to the " +
		"minimum required scopes."
}
func (instanceBroadScope) Severity() ir.Severity { return ir.SeverityHigh }

func (instanceBroadScope) AppliesTo(resType string) bool {
	return resType == "google_compute_instance"
}

func (s instanceBroadScope) Check(r ir.Resource) []ir.Finding {
	sas, _, present, known := getBlocks(r, "service_account")
	if !present || !known {
		return nil
	}
	for _, sa := range sas {
		scopes, span, ok := blockStringList(sa, "scopes")
		if !ok {
			continue // unresolved: cannot decide for this block
		}
		for _, sc := range scopes {
			low := strings.ToLower(strings.TrimSpace(sc))
			if low == "cloud-platform" ||
				strings.HasSuffix(low, "/auth/cloud-platform") {
				return []ir.Finding{mkFinding(s, r,
					"service_account.scopes", span,
					sc, "minimum required scopes only")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-019: Cloud SQL instance without deletion protection
// ---------------------------------------------------------------------------

type sqlNoDeletionProtection struct{}

func (sqlNoDeletionProtection) ID() string { return "AEGIS-GCP-019" }
func (sqlNoDeletionProtection) Title() string {
	return "Cloud SQL instance without deletion protection"
}
func (sqlNoDeletionProtection) Description() string {
	return "google_sql_database_instance with deletion_protection = false " +
		"(the provider default) can be destroyed accidentally. Enable " +
		"deletion protection for production databases."
}
func (sqlNoDeletionProtection) Severity() ir.Severity { return ir.SeverityMedium }

func (sqlNoDeletionProtection) AppliesTo(resType string) bool {
	return resType == "google_sql_database_instance"
}

func (s sqlNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	prot, span, present, known := getBool(r, "deletion_protection")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && prot {
		return nil
	}
	// Absent or false: provider default is unprotected. Documented.
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(s, r, "deletion_protection", span,
		actual, "deletion_protection = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-020: Pub/Sub topic without customer-managed encryption
// ---------------------------------------------------------------------------

type pubsubNoCMEK struct{}

func (pubsubNoCMEK) ID() string { return "AEGIS-GCP-020" }
func (pubsubNoCMEK) Title() string {
	return "Pub/Sub topic without customer-managed encryption"
}
func (pubsubNoCMEK) Description() string {
	return "google_pubsub_topic with no kms_key_name relies on " +
		"Google-managed keys. Set kms_key_name for key control."
}
func (pubsubNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (pubsubNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_pubsub_topic"
}

func (s pubsubNoCMEK) Check(r ir.Resource) []ir.Finding {
	key, _, present, known := getString(r, "kms_key_name")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(key) != "" {
		return nil
	}
	// Absent: Google-managed keys. Documented.
	return []ir.Finding{mkFinding(s, r, "kms_key_name", r.Span,
		"absent", "kms_key_name = google_kms_crypto_key.example.id")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-021: GKE cluster without logging and monitoring
// ---------------------------------------------------------------------------

type gkeNoLogging struct{}

func (gkeNoLogging) ID() string { return "AEGIS-GCP-021" }
func (gkeNoLogging) Title() string {
	return "GKE cluster without logging and monitoring"
}
func (gkeNoLogging) Description() string {
	return "google_container_cluster with logging_service = \"none\" or " +
		"monitoring_service = \"none\" produces no control-plane telemetry."
}
func (gkeNoLogging) Severity() ir.Severity { return ir.SeverityMedium }

func (gkeNoLogging) AppliesTo(resType string) bool {
	return resType == "google_container_cluster"
}

func (s gkeNoLogging) Check(r ir.Resource) []ir.Finding {
	for _, attr := range []string{"logging_service", "monitoring_service"} {
		val, span, present, known := getString(r, attr)
		if !present || !known {
			continue // absent or unresolved: cannot decide for this attr
		}
		if strings.EqualFold(strings.TrimSpace(val), "none") {
			return []ir.Finding{mkFinding(s, r, attr, span,
				val, attr+" = \"logging.googleapis.com/kubernetes\"")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-022: Secret Manager secret without rotation
// ---------------------------------------------------------------------------

type secretNoRotation struct{}

func (secretNoRotation) ID() string { return "AEGIS-GCP-022" }
func (secretNoRotation) Title() string {
	return "Secret Manager secret without rotation"
}
func (secretNoRotation) Description() string {
	return "google_secret_manager_secret with no rotation block never " +
		"rotates. Configure rotation with a rotation_period."
}
func (secretNoRotation) Severity() ir.Severity { return ir.SeverityMedium }

func (secretNoRotation) AppliesTo(resType string) bool {
	return resType == "google_secret_manager_secret"
}

func (s secretNoRotation) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "rotation")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil // rotation configured
	}
	// Absent: no rotation. Documented insecure default.
	return []ir.Finding{mkFinding(s, r, "rotation", r.Span,
		"absent", "rotation { rotation_period = \"7776000s\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-023: Subnetwork without private Google access
// ---------------------------------------------------------------------------

type subnetNoPrivateAccess struct{}

func (subnetNoPrivateAccess) ID() string { return "AEGIS-GCP-023" }
func (subnetNoPrivateAccess) Title() string {
	return "Subnetwork without private Google access"
}
func (subnetNoPrivateAccess) Description() string {
	return "google_compute_subnetwork with private_ip_google_access = false " +
		"forces VMs to use public IPs to reach Google APIs. Enable private " +
		"Google access for internal-only workloads."
}
func (subnetNoPrivateAccess) Severity() ir.Severity { return ir.SeverityMedium }

func (subnetNoPrivateAccess) AppliesTo(resType string) bool {
	return resType == "google_compute_subnetwork"
}

func (s subnetNoPrivateAccess) Check(r ir.Resource) []ir.Finding {
	priv, span, present, known := getBool(r, "private_ip_google_access")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if priv {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "private_ip_google_access", span,
		"false", "private_ip_google_access = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-024: DNS managed zone without DNSSEC
// ---------------------------------------------------------------------------

type dnsNoDNSSEC struct{}

func (dnsNoDNSSEC) ID() string { return "AEGIS-GCP-024" }
func (dnsNoDNSSEC) Title() string {
	return "DNS managed zone without DNSSEC"
}
func (dnsNoDNSSEC) Description() string {
	return "google_dns_managed_zone with no dnssec_config block leaves the " +
		"zone vulnerable to DNS spoofing. Enable DNSSEC."
}
func (dnsNoDNSSEC) Severity() ir.Severity { return ir.SeverityMedium }

func (dnsNoDNSSEC) AppliesTo(resType string) bool {
	return resType == "google_dns_managed_zone"
}

func (s dnsNoDNSSEC) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "dnssec_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil // DNSSEC configured
	}
	// Absent: no DNSSEC. Documented insecure default.
	return []ir.Finding{mkFinding(s, r, "dnssec_config", r.Span,
		"absent", "dnssec_config {}")}
}
