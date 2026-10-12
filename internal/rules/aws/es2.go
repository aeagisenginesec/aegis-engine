package aws

// Elasticsearch/OpenSearch hardening, round 2 (AEGIS-AWS-637..644).
//
// Gaps not covered by AEGIS-AWS-318/319 (node-to-node, at-rest encryption),
// 418/523 (advanced security / fine-grained access control), 507 (VPC),
// 519 (TLS policy) or 618/623 (audit / any log publishing): HTTPS
// enforcement, dedicated master nodes, zone awareness, the internal user
// database, snapshot configuration, slow-query logs, end-of-life engine
// versions, and fine-grained access control on the legacy
// aws_elasticsearch_domain resource.
//
// Unknown-value contract: a present-but-unresolved attribute yields NO
// finding. Absent attributes are judged against the provider's insecure
// default, documented per rule. Rules never panic on unexpected shapes.

import (
	"strings"

	"aegis/internal/ir"
)

// Search2Rules returns the Elasticsearch/OpenSearch rules, AEGIS-AWS-637..644,
// in ID order.
func Search2Rules() []ir.Rule {
	return []ir.Rule{
		esNoEnforceHTTPS{},         // AEGIS-AWS-637
		esNoDedicatedMaster{},      // AEGIS-AWS-638
		esNoZoneAwareness{},        // AEGIS-AWS-639
		opensearchNoInternalUser{}, // AEGIS-AWS-640
		esNoSnapshotOptions{},      // AEGIS-AWS-641
		esNoSlowLogs{},             // AEGIS-AWS-642
		searchOldEngineVersion{},   // AEGIS-AWS-643
		esNoAdvancedSecurity{},     // AEGIS-AWS-644
	}
}

func searchTypes(resType string) bool {
	return resType == "aws_elasticsearch_domain" ||
		resType == "aws_opensearch_domain"
}

func esFinding(rule ir.Rule, r ir.Resource, attr string, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-637: Search domain without HTTPS enforcement
// ---------------------------------------------------------------------------

type esNoEnforceHTTPS struct{}

func (esNoEnforceHTTPS) ID() string { return "AEGIS-AWS-637" }
func (esNoEnforceHTTPS) Title() string {
	return "Elasticsearch/OpenSearch domain without HTTPS enforcement"
}
func (esNoEnforceHTTPS) Description() string {
	return "A search domain whose domain_endpoint_options does not set " +
		"enforce_https = true serves the cluster endpoint over plaintext " +
		"HTTP, exposing credentials and query data in transit."
}
func (esNoEnforceHTTPS) Severity() ir.Severity         { return ir.SeverityHigh }
func (esNoEnforceHTTPS) AppliesTo(resType string) bool { return searchTypes(resType) }

func (s esNoEnforceHTTPS) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "domain_endpoint_options")
	if present && !known {
		return nil // unresolved block: cannot decide
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{esFinding(s, r, "domain_endpoint_options.enforce_https",
			ir.Span{}, "absent (default false)",
			"domain_endpoint_options { enforce_https = true }")}
	}
	enf, _, epresent, eknown := blockBool(blks[0], "enforce_https")
	if epresent && !eknown {
		return nil
	}
	if epresent && enf {
		return nil
	}
	actual := "absent (default false)"
	if epresent {
		actual = "false"
	}
	return []ir.Finding{esFinding(s, r, "domain_endpoint_options.enforce_https",
		ir.Span{}, actual, "enforce_https = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-638: Search domain without dedicated master nodes
// ---------------------------------------------------------------------------

type esNoDedicatedMaster struct{}

func (esNoDedicatedMaster) ID() string { return "AEGIS-AWS-638" }
func (esNoDedicatedMaster) Title() string {
	return "Elasticsearch/OpenSearch domain without dedicated master nodes"
}
func (esNoDedicatedMaster) Description() string {
	return "A search domain whose cluster_config does not set " +
		"dedicated_master_enabled = true runs cluster coordination on data " +
		"nodes, risking split-brain and instability under load. Use " +
		"dedicated master nodes for production domains."
}
func (esNoDedicatedMaster) Severity() ir.Severity         { return ir.SeverityMedium }
func (esNoDedicatedMaster) AppliesTo(resType string) bool { return searchTypes(resType) }

func (s esNoDedicatedMaster) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "cluster_config")
	if present && !known {
		return nil // unresolved block: cannot decide
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{esFinding(s, r, "cluster_config.dedicated_master_enabled",
			ir.Span{}, "absent (default false)",
			"cluster_config { dedicated_master_enabled = true }")}
	}
	dm, _, dpresent, dknown := blockBool(blks[0], "dedicated_master_enabled")
	if dpresent && !dknown {
		return nil
	}
	if dpresent && dm {
		return nil
	}
	actual := "absent (default false)"
	if dpresent {
		actual = "false"
	}
	return []ir.Finding{esFinding(s, r, "cluster_config.dedicated_master_enabled",
		ir.Span{}, actual, "dedicated_master_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-639: Search domain without zone awareness
// ---------------------------------------------------------------------------

type esNoZoneAwareness struct{}

func (esNoZoneAwareness) ID() string { return "AEGIS-AWS-639" }
func (esNoZoneAwareness) Title() string {
	return "Elasticsearch/OpenSearch domain without zone awareness"
}
func (esNoZoneAwareness) Description() string {
	return "A search domain whose cluster_config does not set " +
		"zone_awareness_enabled = true places all nodes in one availability " +
		"zone: a zone failure takes the domain down. Enable zone awareness " +
		"for multi-AZ resilience."
}
func (esNoZoneAwareness) Severity() ir.Severity         { return ir.SeverityMedium }
func (esNoZoneAwareness) AppliesTo(resType string) bool { return searchTypes(resType) }

func (s esNoZoneAwareness) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "cluster_config")
	if present && !known {
		return nil // unresolved block: cannot decide
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{esFinding(s, r, "cluster_config.zone_awareness_enabled",
			ir.Span{}, "absent (default false)",
			"cluster_config { zone_awareness_enabled = true }")}
	}
	za, _, zpresent, zknown := blockBool(blks[0], "zone_awareness_enabled")
	if zpresent && !zknown {
		return nil
	}
	if zpresent && za {
		return nil
	}
	actual := "absent (default false)"
	if zpresent {
		actual = "false"
	}
	return []ir.Finding{esFinding(s, r, "cluster_config.zone_awareness_enabled",
		ir.Span{}, actual, "zone_awareness_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-640: OpenSearch domain without internal user database
// ---------------------------------------------------------------------------

type opensearchNoInternalUser struct{}

func (opensearchNoInternalUser) ID() string { return "AEGIS-AWS-640" }
func (opensearchNoInternalUser) Title() string {
	return "OpenSearch domain without internal user database"
}
func (opensearchNoInternalUser) Description() string {
	return "An OpenSearch domain whose advanced_security_options does not " +
		"set internal_user_database_enabled = true has no built-in master " +
		"user store, weakening fine-grained access control. Enable the " +
		"internal user database."
}
func (opensearchNoInternalUser) Severity() ir.Severity { return ir.SeverityMedium }
func (opensearchNoInternalUser) AppliesTo(resType string) bool {
	return resType == "aws_opensearch_domain"
}

func (s opensearchNoInternalUser) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "advanced_security_options")
	if present && !known {
		return nil // unresolved block: cannot decide
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{esFinding(s, r,
			"advanced_security_options.internal_user_database_enabled",
			ir.Span{}, "absent (default false)",
			"advanced_security_options { internal_user_database_enabled = true }")}
	}
	iu, _, ipresent, iknown := blockBool(blks[0], "internal_user_database_enabled")
	if ipresent && !iknown {
		return nil
	}
	if ipresent && iu {
		return nil
	}
	actual := "absent (default false)"
	if ipresent {
		actual = "false"
	}
	return []ir.Finding{esFinding(s, r,
		"advanced_security_options.internal_user_database_enabled",
		ir.Span{}, actual, "internal_user_database_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-641: Search domain without snapshot configuration
// ---------------------------------------------------------------------------

type esNoSnapshotOptions struct{}

func (esNoSnapshotOptions) ID() string { return "AEGIS-AWS-641" }
func (esNoSnapshotOptions) Title() string {
	return "Elasticsearch/OpenSearch domain without snapshot configuration"
}
func (esNoSnapshotOptions) Description() string {
	return "Hygiene: a search domain without a snapshot_options block has " +
		"no configured automated snapshot schedule, slowing recovery from " +
		"data loss or corruption. Set automated_snapshot_start_hour."
}
func (esNoSnapshotOptions) Severity() ir.Severity         { return ir.SeverityLow }
func (esNoSnapshotOptions) AppliesTo(resType string) bool { return searchTypes(resType) }

func (s esNoSnapshotOptions) Check(r ir.Resource) []ir.Finding {
	if _, _, present, _ := getBlocks(r, "snapshot_options"); present {
		return nil
	}
	return []ir.Finding{esFinding(s, r, "snapshot_options",
		ir.Span{}, "absent",
		"snapshot_options { automated_snapshot_start_hour = 3 }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-642: Search domain without slow logs
// ---------------------------------------------------------------------------

type esNoSlowLogs struct{}

func (esNoSlowLogs) ID() string { return "AEGIS-AWS-642" }
func (esNoSlowLogs) Title() string {
	return "Elasticsearch/OpenSearch domain without slow logs"
}
func (esNoSlowLogs) Description() string {
	return "Hygiene: a search domain whose log_publishing_options publish " +
		"neither SEARCH_SLOW_LOGS nor INDEX_SLOW_LOGS hides expensive " +
		"queries, blinding performance tuning and abuse detection. Publish " +
		"slow logs. (Audit-specific coverage: AEGIS-AWS-618; any-log " +
		"coverage: AEGIS-AWS-623.)"
}
func (esNoSlowLogs) Severity() ir.Severity         { return ir.SeverityLow }
func (esNoSlowLogs) AppliesTo(resType string) bool { return searchTypes(resType) }

func (s esNoSlowLogs) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "log_publishing_options")
	if present && !known {
		return nil
	}
	for _, b := range blks {
		lt, _, lpresent, lknown := blockString(b, "log_type")
		if lpresent && !lknown {
			return nil // unresolved: cannot decide
		}
		if lpresent && strings.Contains(strings.ToUpper(lt), "SLOW_LOGS") {
			return nil // slow logging present
		}
	}
	return []ir.Finding{esFinding(s, r, "log_publishing_options",
		ir.Span{}, "no SEARCH_SLOW_LOGS / INDEX_SLOW_LOGS option",
		"log_publishing_options with log_type SEARCH_SLOW_LOGS")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-643: Search domain on an end-of-life engine version
// ---------------------------------------------------------------------------

type searchOldEngineVersion struct{}

func (searchOldEngineVersion) ID() string { return "AEGIS-AWS-643" }
func (searchOldEngineVersion) Title() string {
	return "Elasticsearch/OpenSearch domain on an end-of-life engine version"
}
func (searchOldEngineVersion) Description() string {
	return "A search domain pinned to an end-of-life engine version " +
		"(Elasticsearch below 7.x) no longer receives security patches. " +
		"Upgrade to a supported engine version."
}
func (searchOldEngineVersion) Severity() ir.Severity         { return ir.SeverityMedium }
func (searchOldEngineVersion) AppliesTo(resType string) bool { return searchTypes(resType) }

func (s searchOldEngineVersion) Check(r ir.Resource) []ir.Finding {
	attr := "elasticsearch_version"
	if r.Type == "aws_opensearch_domain" {
		attr = "engine_version"
	}
	ver, span, present, known := getString(r, attr)
	if !present || !known {
		return nil
	}
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return nil
	}
	old := false
	if r.Type == "aws_elasticsearch_domain" {
		// Only versions with a leading major < 7 are unambiguously EOL.
		major := strings.SplitN(ver, ".", 2)[0]
		switch major {
		case "1", "2", "3", "4", "5", "6":
			old = true
		}
	}
	// aws_opensearch_domain engine_version ("OpenSearch_X.Y"): no
	// unambiguously-EOL cutoff applied; stay quiet.
	if !old {
		return nil
	}
	return []ir.Finding{esFinding(s, r, attr, span, ver,
		"elasticsearch_version >= \"7.0\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-644: Elasticsearch domain without fine-grained access control
// ---------------------------------------------------------------------------

type esNoAdvancedSecurity struct{}

func (esNoAdvancedSecurity) ID() string { return "AEGIS-AWS-644" }
func (esNoAdvancedSecurity) Title() string {
	return "Elasticsearch domain without fine-grained access control"
}
func (esNoAdvancedSecurity) Description() string {
	return "An aws_elasticsearch_domain without advanced_security_options " +
		"(enabled = true) has no fine-grained access control: any principal " +
		"reaching the endpoint can read and write any index. Enable " +
		"advanced security with a master user. (OpenSearch coverage: " +
		"AEGIS-AWS-418/523.)"
}
func (esNoAdvancedSecurity) Severity() ir.Severity { return ir.SeverityMedium }
func (esNoAdvancedSecurity) AppliesTo(resType string) bool {
	return resType == "aws_elasticsearch_domain"
}

func (s esNoAdvancedSecurity) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "advanced_security_options")
	if !present {
		return []ir.Finding{esFinding(s, r, "advanced_security_options",
			ir.Span{}, "absent",
			"advanced_security_options { enabled = true ... }")}
	}
	if !known || len(blks) == 0 {
		return nil
	}
	enabled, _, epresent, eknown := blockBool(blks[0], "enabled")
	if epresent && !eknown {
		return nil
	}
	if epresent && enabled {
		return nil
	}
	actual := "absent"
	if epresent {
		actual = "false"
	}
	return []ir.Finding{esFinding(s, r, "advanced_security_options.enabled",
		ir.Span{}, actual, "enabled = true")}
}
