// Package gcp — extended rule pack part 4 (AEGIS-GCP-101..122).
//
// Checkov gap-closure pack: Cloud SQL PostgreSQL audit flags, GKE cluster
// hardening (metadata server, binary authorization, ABAC, network policy,
// private cluster, control-plane exposure, release channel, Stackdriver
// logging), GKE node-pool management, Compute (IP forwarding, serial port,
// subnetwork flow logs), and Storage (uniform access, public access
// prevention).
package gcp

import (
	"strings"

	"aegis/internal/ir"
)

// GCP4Rules returns the Checkov gap-closure GCP rules in ID order.
func GCP4Rules() []ir.Rule {
	return []ir.Rule{
		// Cloud SQL PostgreSQL flags 101-107
		sqlNoLogCheckpoints{}, sqlNoLogConnections{}, sqlNoLogDisconnectionsPg{},
		sqlNoLogLockWaits{}, sqlNoLogDuration{}, sqlNoPgAudit{},
		sqlLogMinMessages{},
		// GKE cluster 108-115
		gkeNoMetadataServer{}, gkeBinaryAuthDisabled{},
		gkeNoNetworkPolicyGap{}, gkePublicControlPlane{},
		gkeNoReleaseChannel{}, gkeNoStackdriverLogging{},
		// GKE node pool 116-117
		nodePoolNoAutoRepair{}, nodePoolNoAutoUpgrade{},
		// Compute 120 (118-119 removed as duplicates of 057/058)
		subnetworkNoFlowLogs{},
		// Storage 122 removed as exact duplicate of 032 (same PAP condition,
		// inconsistent High vs Medium severity; 032 kept as canonical)
	}
}

// ---------------------------------------------------------------------------
// Shared: Cloud SQL database flags
// ---------------------------------------------------------------------------

// sqlFlagValue scans settings.database_flags for the named flag, returning
// its value. found=false when the flag is absent; known=false when the
// value is unresolved or missing.
func sqlFlagValue(st map[string]ir.Value, name string) (val string, span ir.Span, found, known bool) {
	for _, f := range blockList(st, "database_flags") {
		n, _, np, nk := getString(mapRes(f), "name")
		if !np || !nk || !strings.EqualFold(strings.TrimSpace(n), name) {
			continue
		}
		v, vspan, vp, vk := getString(mapRes(f), "value")
		if !vp {
			return "", ir.Span{}, true, false
		}
		return v, vspan, true, vk
	}
	return "", ir.Span{}, false, false
}

// sqlIsPostgres reports whether the Cloud SQL instance is PostgreSQL.
// PostgreSQL-only flags (log_checkpoints, pgaudit, …) must not fire on
// MySQL/SQL Server instances. When database_version is absent or
// unresolved the engine is unknown and the check proceeds as before;
// only an explicit non-PostgreSQL engine suppresses the finding.
func sqlIsPostgres(r ir.Resource) bool {
	v, _, present, known := getString(r, "database_version")
	if !present || !known {
		return true
	}
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(v)), "POSTGRES")
}

// sqlFlagOn returns a finding when the named PostgreSQL flag is absent from
// settings.database_flags, or present with a value other than on/1.
func sqlFlagOn(rule ir.Rule, r ir.Resource, flag, remediation string) []ir.Finding {
	if !sqlIsPostgres(r) {
		return nil
	}
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		val, _, found, fknown := sqlFlagValue(st, flag)
		if found {
			if !fknown {
				return nil
			}
			if strings.ToLower(strings.TrimSpace(val)) == "on" || val == "1" {
				return nil
			}
			return []ir.Finding{mkFinding(rule, r, "settings.database_flags."+flag,
				r.Span, flag+"="+val, remediation)}
		}
	}
	return []ir.Finding{mkFinding(rule, r, "settings.database_flags", r.Span,
		flag+" not set", remediation)}
}

// ---------------------------------------------------------------------------
// Cloud SQL PostgreSQL flags: AEGIS-GCP-101..107
// ---------------------------------------------------------------------------

// AEGIS-GCP-101: Cloud SQL PostgreSQL without log_checkpoints
type sqlNoLogCheckpoints struct{}

func (sqlNoLogCheckpoints) ID() string { return "AEGIS-GCP-101" }
func (sqlNoLogCheckpoints) Title() string {
	return "Cloud SQL PostgreSQL without log_checkpoints"
}
func (sqlNoLogCheckpoints) Description() string {
	return "google_sql_database_instance (PostgreSQL) without database flag " +
		"log_checkpoints=on misses checkpoint timing and buffer-write " +
		"audit data."
}
func (sqlNoLogCheckpoints) Severity() ir.Severity { return ir.SeverityLow }
func (sqlNoLogCheckpoints) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoLogCheckpoints) Check(r ir.Resource) []ir.Finding {
	return sqlFlagOn(s, r, "log_checkpoints",
		"database_flags { name = \"log_checkpoints\" value = \"on\" }")
}

// AEGIS-GCP-102: Cloud SQL PostgreSQL without log_connections
type sqlNoLogConnections struct{}

func (sqlNoLogConnections) ID() string { return "AEGIS-GCP-102" }
func (sqlNoLogConnections) Title() string {
	return "Cloud SQL PostgreSQL without log_connections"
}
func (sqlNoLogConnections) Description() string {
	return "google_sql_database_instance (PostgreSQL) without database flag " +
		"log_connections=on misses connection-attempt audit data."
}
func (sqlNoLogConnections) Severity() ir.Severity { return ir.SeverityLow }
func (sqlNoLogConnections) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoLogConnections) Check(r ir.Resource) []ir.Finding {
	return sqlFlagOn(s, r, "log_connections",
		"database_flags { name = \"log_connections\" value = \"on\" }")
}

// AEGIS-GCP-103: Cloud SQL PostgreSQL without log_disconnections (gap pair)
type sqlNoLogDisconnectionsPg struct{}

func (sqlNoLogDisconnectionsPg) ID() string { return "AEGIS-GCP-103" }
func (sqlNoLogDisconnectionsPg) Title() string {
	return "Cloud SQL PostgreSQL without log_disconnections"
}
func (sqlNoLogDisconnectionsPg) Description() string {
	return "google_sql_database_instance (PostgreSQL) without database flag " +
		"log_disconnections=on misses session-termination audit data."
}
func (sqlNoLogDisconnectionsPg) Severity() ir.Severity { return ir.SeverityLow }
func (sqlNoLogDisconnectionsPg) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoLogDisconnectionsPg) Check(r ir.Resource) []ir.Finding {
	return sqlFlagOn(s, r, "log_disconnections",
		"database_flags { name = \"log_disconnections\" value = \"on\" }")
}

// AEGIS-GCP-104: Cloud SQL PostgreSQL without log_lock_waits
type sqlNoLogLockWaits struct{}

func (sqlNoLogLockWaits) ID() string { return "AEGIS-GCP-104" }
func (sqlNoLogLockWaits) Title() string {
	return "Cloud SQL PostgreSQL without log_lock_waits"
}
func (sqlNoLogLockWaits) Description() string {
	return "google_sql_database_instance (PostgreSQL) without database flag " +
		"log_lock_waits=on misses deadlock-risk visibility into sessions " +
		"waiting longer than deadlock_timeout."
}
func (sqlNoLogLockWaits) Severity() ir.Severity { return ir.SeverityLow }
func (sqlNoLogLockWaits) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoLogLockWaits) Check(r ir.Resource) []ir.Finding {
	return sqlFlagOn(s, r, "log_lock_waits",
		"database_flags { name = \"log_lock_waits\" value = \"on\" }")
}

// AEGIS-GCP-105: Cloud SQL PostgreSQL without log_duration
type sqlNoLogDuration struct{}

func (sqlNoLogDuration) ID() string { return "AEGIS-GCP-105" }
func (sqlNoLogDuration) Title() string {
	return "Cloud SQL PostgreSQL without log_duration"
}
func (sqlNoLogDuration) Description() string {
	return "google_sql_database_instance (PostgreSQL) without database flag " +
		"log_duration=on misses per-statement duration logging needed to " +
		"detect anomalous query timing."
}
func (sqlNoLogDuration) Severity() ir.Severity { return ir.SeverityLow }
func (sqlNoLogDuration) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoLogDuration) Check(r ir.Resource) []ir.Finding {
	return sqlFlagOn(s, r, "log_duration",
		"database_flags { name = \"log_duration\" value = \"on\" }")
}

// AEGIS-GCP-106: Cloud SQL PostgreSQL without pgAudit
type sqlNoPgAudit struct{}

func (sqlNoPgAudit) ID() string { return "AEGIS-GCP-106" }
func (sqlNoPgAudit) Title() string {
	return "Cloud SQL PostgreSQL without pgAudit logging"
}
func (sqlNoPgAudit) Description() string {
	return "google_sql_database_instance (PostgreSQL) without pgAudit " +
		"(pgaudit.log with READ,WRITE or shared_preload_libraries containing " +
		"pgaudit) misses detailed session/object audit logging."
}
func (sqlNoPgAudit) Severity() ir.Severity { return ir.SeverityMedium }
func (sqlNoPgAudit) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlNoPgAudit) Check(r ir.Resource) []ir.Finding {
	if !sqlIsPostgres(r) {
		return nil
	}
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		// pgaudit.log must contain both READ and WRITE
		if val, _, found, fknown := sqlFlagValue(st, "pgaudit.log"); found {
			if !fknown {
				return nil
			}
			upper := strings.ToUpper(val)
			if strings.Contains(upper, "READ") && strings.Contains(upper, "WRITE") {
				return nil
			}
		}
		// shared_preload_libraries containing pgaudit
		if val, _, found, fknown := sqlFlagValue(st, "shared_preload_libraries"); found {
			if !fknown {
				return nil
			}
			if strings.Contains(strings.ToLower(val), "pgaudit") {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "settings.database_flags", r.Span,
		"pgAudit not enabled",
		"database_flags { name = \"pgaudit.log\" value = \"READ,WRITE\" } and "+
			"database_flags { name = \"shared_preload_libraries\" value = \"pgaudit\" }")}
}

// AEGIS-GCP-107: Cloud SQL PostgreSQL log_min_messages too verbose
type sqlLogMinMessages struct{}

func (sqlLogMinMessages) ID() string { return "AEGIS-GCP-107" }
func (sqlLogMinMessages) Title() string {
	return "Cloud SQL PostgreSQL log_min_messages not set appropriately"
}
func (sqlLogMinMessages) Description() string {
	return "google_sql_database_instance (PostgreSQL) without database flag " +
		"log_min_messages set to WARNING or more severe emits overly " +
		"verbose logs (or none at all), burying security-relevant messages."
}
func (sqlLogMinMessages) Severity() ir.Severity { return ir.SeverityLow }
func (sqlLogMinMessages) AppliesTo(t string) bool {
	return t == "google_sql_database_instance"
}
func (s sqlLogMinMessages) Check(r ir.Resource) []ir.Finding {
	if !sqlIsPostgres(r) {
		return nil
	}
	settings, _, present, known := getBlocks(r, "settings")
	if !present || !known {
		return nil
	}
	for _, st := range settings {
		val, span, found, fknown := sqlFlagValue(st, "log_min_messages")
		if found {
			if !fknown {
				return nil
			}
			switch strings.ToUpper(strings.TrimSpace(val)) {
			case "PANIC", "FATAL", "ERROR", "WARNING":
				return nil
			}
			return []ir.Finding{mkFinding(s, r, "settings.database_flags.log_min_messages",
				span, val,
				"database_flags { name = \"log_min_messages\" value = \"WARNING\" }")}
		}
	}
	return []ir.Finding{mkFinding(s, r, "settings.database_flags", r.Span,
		"log_min_messages not set",
		"database_flags { name = \"log_min_messages\" value = \"WARNING\" }")}
}

// ---------------------------------------------------------------------------
// GKE cluster: AEGIS-GCP-108..115
// ---------------------------------------------------------------------------

// AEGIS-GCP-108: GKE without metadata server / workload identity
type gkeNoMetadataServer struct{}

func (gkeNoMetadataServer) ID() string { return "AEGIS-GCP-108" }
func (gkeNoMetadataServer) Title() string {
	return "GKE cluster without metadata server v2"
}
func (gkeNoMetadataServer) Description() string {
	return "google_container_cluster with no workload_identity_config and " +
		"no node_config.workload_metadata_config.mode = GKE_METADATA " +
		"exposes the legacy metadata server to workloads."
}
func (gkeNoMetadataServer) Severity() ir.Severity { return ir.SeverityMedium }
func (gkeNoMetadataServer) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeNoMetadataServer) Check(r ir.Resource) []ir.Finding {
	wic, _, present, known := getBlocks(r, "workload_identity_config")
	if present && !known {
		return nil
	}
	if present && len(wic) > 0 {
		return nil // workload identity implies metadata server v2
	}
	ncs, _, ncp, nck := getBlocks(r, "node_config")
	if ncp && !nck {
		return nil
	}
	for _, nc := range ncs {
		for _, w := range blockList(nc, "workload_metadata_config") {
			mode, _, mp, mk := getString(mapRes(w), "mode")
			if !mp || !mk {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(mode), "GKE_METADATA") {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "workload_identity_config", r.Span,
		"absent (metadata server v2 not enforced)",
		"workload_identity_config { workload_pool = \"...svc.id.goog\" } or "+
			"node_config { workload_metadata_config { mode = \"GKE_METADATA\" } }")}
}

// AEGIS-GCP-109: GKE binary authorization not enabled
type gkeBinaryAuthDisabled struct{}

func (gkeBinaryAuthDisabled) ID() string { return "AEGIS-GCP-109" }
func (gkeBinaryAuthDisabled) Title() string {
	return "GKE cluster with binary authorization disabled"
}
func (gkeBinaryAuthDisabled) Description() string {
	return "google_container_cluster with binary_authorization.enabled not " +
		"true deploys container images without admission-time verification."
}
func (gkeBinaryAuthDisabled) Severity() ir.Severity { return ir.SeverityMedium }
func (gkeBinaryAuthDisabled) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeBinaryAuthDisabled) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "binary_authorization")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "binary_authorization", r.Span,
			"absent", "binary_authorization { enabled = true }")}
	}
	en, span, p, k := blockBool(blks[0], "enabled")
	if !p {
		// modern provider form: evaluation_mode
		mode, _, mp, mk := getString(mapRes(blks[0]), "evaluation_mode")
		if mp && mk && strings.TrimSpace(mode) != "" {
			return nil
		}
		return []ir.Finding{mkFinding(s, r, "binary_authorization.enabled", r.Span,
			"absent", "binary_authorization { enabled = true }")}
	}
	if !k {
		return nil
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "binary_authorization.enabled", span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-110: GKE with legacy ABAC enabled

// AEGIS-GCP-111: GKE without network policy
type gkeNoNetworkPolicyGap struct{}

func (gkeNoNetworkPolicyGap) ID() string { return "AEGIS-GCP-111" }
func (gkeNoNetworkPolicyGap) Title() string {
	return "GKE cluster without network policy enforcement"
}
func (gkeNoNetworkPolicyGap) Description() string {
	return "google_container_cluster with network_policy.enabled not true " +
		"cannot enforce pod-level network segmentation."
}
func (gkeNoNetworkPolicyGap) Severity() ir.Severity { return ir.SeverityMedium }
func (gkeNoNetworkPolicyGap) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeNoNetworkPolicyGap) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "network_policy")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "network_policy", r.Span,
			"absent", "network_policy { enabled = true }")}
	}
	en, span, p, k := blockBool(blks[0], "enabled")
	if !p {
		return []ir.Finding{mkFinding(s, r, "network_policy.enabled", r.Span,
			"absent", "network_policy { enabled = true }")}
	}
	if !k {
		return nil
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "network_policy.enabled", span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-112: GKE not a private cluster

// AEGIS-GCP-113: GKE control plane publicly reachable
type gkePublicControlPlane struct{}

func (gkePublicControlPlane) ID() string { return "AEGIS-GCP-113" }
func (gkePublicControlPlane) Title() string {
	return "GKE control plane publicly reachable"
}
func (gkePublicControlPlane) Description() string {
	return "google_container_cluster with no private endpoint and " +
		"master_authorized_networks_config absent or allowing 0.0.0.0/0 " +
		"exposes the Kubernetes API to the internet."
}
func (gkePublicControlPlane) Severity() ir.Severity { return ir.SeverityHigh }
func (gkePublicControlPlane) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkePublicControlPlane) Check(r ir.Resource) []ir.Finding {
	pcc, _, pccPresent, pccKnown := getBlocks(r, "private_cluster_config")
	if pccPresent && !pccKnown {
		return nil
	}
	for _, b := range pcc {
		en, _, p, k := blockBool(b, "enable_private_endpoint")
		if p && k && en {
			return nil // control plane is private
		}
	}
	manc, _, mancPresent, mancKnown := getBlocks(r, "master_authorized_networks_config")
	if mancPresent && !mancKnown {
		return nil
	}
	remediation := "private_cluster_config { enable_private_endpoint = true } or " +
		"master_authorized_networks_config with restricted cidr_blocks"
	if !mancPresent || len(manc) == 0 {
		return []ir.Finding{mkFinding(s, r, "master_authorized_networks_config", r.Span,
			"absent (control plane open to the internet)", remediation)}
	}
	worldOpen, sawCIDR := false, false
	for _, m := range manc {
		for _, cb := range blockList(m, "cidr_blocks") {
			cidr, _, p, k := getString(mapRes(cb), "cidr_block")
			if !p || !k {
				cidr, _, p, k = getString(mapRes(cb), "cidr")
			}
			if !p || !k {
				continue
			}
			sawCIDR = true
			if strings.TrimSpace(cidr) == "0.0.0.0/0" {
				worldOpen = true
			}
		}
	}
	if worldOpen {
		return []ir.Finding{mkFinding(s, r, "master_authorized_networks_config.cidr_blocks",
			r.Span, "0.0.0.0/0", remediation)}
	}
	if !sawCIDR {
		return []ir.Finding{mkFinding(s, r, "master_authorized_networks_config", r.Span,
			"no restricted cidr_blocks", remediation)}
	}
	return nil
}

// AEGIS-GCP-114: GKE without release channel
type gkeNoReleaseChannel struct{}

func (gkeNoReleaseChannel) ID() string { return "AEGIS-GCP-114" }
func (gkeNoReleaseChannel) Title() string {
	return "GKE cluster without a release channel"
}
func (gkeNoReleaseChannel) Description() string {
	return "google_container_cluster with no release_channel.channel misses " +
		"managed automatic upgrades to supported Kubernetes versions; " +
		"hygiene finding."
}
func (gkeNoReleaseChannel) Severity() ir.Severity { return ir.SeverityLow }
func (gkeNoReleaseChannel) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeNoReleaseChannel) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "release_channel")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "release_channel", r.Span,
			"absent", "release_channel { channel = \"REGULAR\" }")}
	}
	ch, span, p, k := getString(mapRes(blks[0]), "channel")
	if !p || (k && strings.TrimSpace(ch) == "") {
		return []ir.Finding{mkFinding(s, r, "release_channel.channel",
			evidenceSpan(span, r.Span), "absent or empty",
			"release_channel { channel = \"REGULAR\" }")}
	}
	if !k {
		return nil
	}
	return nil
}

// AEGIS-GCP-115: GKE with Stackdriver logging disabled
type gkeNoStackdriverLogging struct{}

func (gkeNoStackdriverLogging) ID() string { return "AEGIS-GCP-115" }
func (gkeNoStackdriverLogging) Title() string {
	return "GKE cluster with Stackdriver logging disabled"
}
func (gkeNoStackdriverLogging) Description() string {
	return "google_container_cluster with logging_service = \"none\" sends " +
		"no cluster or workload logs to Cloud Logging; hygiene finding."
}
func (gkeNoStackdriverLogging) Severity() ir.Severity { return ir.SeverityLow }
func (gkeNoStackdriverLogging) AppliesTo(t string) bool {
	return t == "google_container_cluster"
}
func (s gkeNoStackdriverLogging) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "logging_service")
	if !present || !known {
		return nil // provider default sends logs
	}
	if strings.EqualFold(strings.TrimSpace(v), "none") {
		return []ir.Finding{mkFinding(s, r, "logging_service", span,
			"none", "logging.googleapis.com (or omitted)")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GKE node pool: AEGIS-GCP-116..117
// ---------------------------------------------------------------------------

// nodePoolManagement reads management.auto_repair / auto_upgrade with the
// "absent means disabled" contract.
func nodePoolManagement(rule ir.Rule, r ir.Resource, attr string) []ir.Finding {
	blks, _, present, known := getBlocks(r, "management")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{mkFinding(rule, r, "management", r.Span,
			"absent", "management { "+attr+" = true }")}
	}
	en, span, p, k := blockBool(blks[0], attr)
	if !p {
		return []ir.Finding{mkFinding(rule, r, "management."+attr, r.Span,
			"absent", attr+" = true")}
	}
	if !k {
		return nil
	}
	if !en {
		return []ir.Finding{mkFinding(rule, r, "management."+attr, span,
			"false", "true")}
	}
	return nil
}

// AEGIS-GCP-116: GKE node pool without auto-repair
type nodePoolNoAutoRepair struct{}

func (nodePoolNoAutoRepair) ID() string { return "AEGIS-GCP-116" }
func (nodePoolNoAutoRepair) Title() string {
	return "GKE node pool without auto-repair"
}
func (nodePoolNoAutoRepair) Description() string {
	return "google_container_node_pool with management.auto_repair not " +
		"true leaves unhealthy nodes running instead of recreating them."
}
func (nodePoolNoAutoRepair) Severity() ir.Severity { return ir.SeverityMedium }
func (nodePoolNoAutoRepair) AppliesTo(t string) bool {
	return t == "google_container_node_pool"
}
func (s nodePoolNoAutoRepair) Check(r ir.Resource) []ir.Finding {
	return nodePoolManagement(s, r, "auto_repair")
}

// AEGIS-GCP-117: GKE node pool without auto-upgrade
type nodePoolNoAutoUpgrade struct{}

func (nodePoolNoAutoUpgrade) ID() string { return "AEGIS-GCP-117" }
func (nodePoolNoAutoUpgrade) Title() string {
	return "GKE node pool without auto-upgrade"
}
func (nodePoolNoAutoUpgrade) Description() string {
	return "google_container_node_pool with management.auto_upgrade not " +
		"true misses security patches to node software."
}
func (nodePoolNoAutoUpgrade) Severity() ir.Severity { return ir.SeverityMedium }
func (nodePoolNoAutoUpgrade) AppliesTo(t string) bool {
	return t == "google_container_node_pool"
}
func (s nodePoolNoAutoUpgrade) Check(r ir.Resource) []ir.Finding {
	return nodePoolManagement(s, r, "auto_upgrade")
}

// ---------------------------------------------------------------------------
// Compute: AEGIS-GCP-118..120

// AEGIS-GCP-119: Compute instance with serial port access enabled

// AEGIS-GCP-120: Compute subnetwork without flow logs
type subnetworkNoFlowLogs struct{}

func (subnetworkNoFlowLogs) ID() string { return "AEGIS-GCP-120" }
func (subnetworkNoFlowLogs) Title() string {
	return "Compute subnetwork without VPC flow logs"
}
func (subnetworkNoFlowLogs) Description() string {
	return "google_compute_subnetwork with no log_config block records no " +
		"VPC flow logs for the subnet; hygiene finding."
}
func (subnetworkNoFlowLogs) Severity() ir.Severity { return ir.SeverityLow }
func (subnetworkNoFlowLogs) AppliesTo(t string) bool {
	return t == "google_compute_subnetwork"
}
func (s subnetworkNoFlowLogs) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBlocks(r, "log_config")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "log_config", r.Span,
			"absent",
			"log_config { aggregation_interval = \"INTERVAL_5_SEC\" flow_sampling = 0.5 "+
				"metadata = \"INCLUDE_ALL_METADATA\" }")}
	}
	return nil
}

