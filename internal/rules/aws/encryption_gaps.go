package aws

import (
	"encoding/json"
	"strings"

	"aegis/internal/ir"
)

// EncryptionGapRules returns the Tier-3 encryption-gap rules (AEGIS-AWS-514-520).
func EncryptionGapRules() []ir.Rule {
	return []ir.Rule{
		elasticacheNoAuthToken{},    // AEGIS-AWS-514
		ecrNoKMS{},                  // AEGIS-AWS-515
		emrNoTransitEncryption{},    // AEGIS-AWS-516
		emrNoLocalDiskEncryption{},  // AEGIS-AWS-517
		daxNoTLS{},                  // AEGIS-AWS-518
		searchOutdatedTLS{},         // AEGIS-AWS-519
		transferOldSecurityPolicy{}, // AEGIS-AWS-520
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-514: ElastiCache replication group with in-transit encryption
// but no auth token (Checkov CKV_AWS_31)
// ---------------------------------------------------------------------------

type elasticacheNoAuthToken struct{}

func (elasticacheNoAuthToken) ID() string { return "AEGIS-AWS-514" }
func (elasticacheNoAuthToken) Title() string {
	return "ElastiCache replication group without auth token"
}
func (elasticacheNoAuthToken) Description() string {
	return "When transit encryption is enabled on an ElastiCache replication " +
		"group, an auth token is required for Redis AUTH. Without one, any " +
		"client that can reach the endpoint authenticates trivially."
}
func (elasticacheNoAuthToken) Severity() ir.Severity { return ir.SeverityHigh }

func (elasticacheNoAuthToken) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}

func (elasticacheNoAuthToken) Check(r ir.Resource) []ir.Finding {
	transit, _, present, known := getBool(r, "transit_encryption_enabled")
	if !present || !known || !transit {
		return nil // not in scope: transit encryption off/absent/unresolved
	}
	token, tspan, tpresent, tknown := getString(r, "auth_token")
	if tpresent && !tknown {
		return nil // unresolved: cannot decide
	}
	if tpresent && strings.TrimSpace(token) != "" {
		return nil // auth token set
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-514",
		Title:       (elasticacheNoAuthToken{}).Title(),
		Description: (elasticacheNoAuthToken{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "auth_token",
			Span:      evidenceSpan(tspan, r.Span),
			Actual:    "absent",
			Expected:  "auth_token set when transit_encryption_enabled is true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-515: ECR repository without KMS encryption (Checkov CKV_AWS_136)
// ---------------------------------------------------------------------------

type ecrNoKMS struct{}

func (ecrNoKMS) ID() string { return "AEGIS-AWS-515" }
func (ecrNoKMS) Title() string {
	return "ECR repository without KMS encryption"
}
func (ecrNoKMS) Description() string {
	return "ECR repositories default to AES256-managed encryption. A customer " +
		"managed KMS key (encryption_type = KMS) gives key control and audit. " +
		"Absent configuration defaults to AES256."
}
func (ecrNoKMS) Severity() ir.Severity { return ir.SeverityMedium }

func (ecrNoKMS) AppliesTo(resType string) bool {
	return resType == "aws_ecr_repository"
}

func (ecrNoKMS) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "encryption_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-515",
			Title:       (ecrNoKMS{}).Title(),
			Description: (ecrNoKMS{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "encryption_configuration",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent (defaults to AES256)",
				Expected:  "encryption_configuration with encryption_type = \"KMS\"",
			},
		}}
	}
	etype, espan, epresent, eknown := blockString(blks[0], "encryption_type")
	if epresent && !eknown {
		return nil // unresolved: cannot decide
	}
	if epresent && strings.EqualFold(strings.TrimSpace(etype), "KMS") {
		return nil // KMS encrypted
	}
	actual := "absent (defaults to AES256)"
	if epresent {
		actual = etype
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-515",
		Title:       (ecrNoKMS{}).Title(),
		Description: (ecrNoKMS{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "encryption_configuration.encryption_type",
			Span:      evidenceSpan(espan, evidenceSpan(span, r.Span)),
			Actual:    actual,
			Expected:  "encryption_type = \"KMS\"",
		},
	}}
}

// ---------------------------------------------------------------------------
// EMR helpers: the aws_emr_security_configuration "configuration" attribute
// is a JSON string like:
//   {"EncryptionConfiguration": {"EnableInTransitEncryption": true,
//                                "EnableAtRestEncryption": true, ...}}
// Returns (encryptionConfig, ok). ok is false when the JSON is absent,
// unparseable, or the EncryptionConfiguration object is missing —
// in all of which the caller must stay silent.
// ---------------------------------------------------------------------------

func emrEncryptionConfig(r ir.Resource) (map[string]any, bool) {
	raw, _, present, known := getString(r, "configuration")
	if !present || !known || strings.TrimSpace(raw) == "" {
		return nil, false
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, false
	}
	enc, ok := doc["EncryptionConfiguration"].(map[string]any)
	if !ok {
		return nil, false
	}
	return enc, true
}

func emrConfigBool(enc map[string]any, key string) (val bool, present bool) {
	v, ok := enc[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-516: EMR security configuration without in-transit encryption
// (Checkov CKV_AWS_351)
// ---------------------------------------------------------------------------

type emrNoTransitEncryption struct{}

func (emrNoTransitEncryption) ID() string { return "AEGIS-AWS-516" }
func (emrNoTransitEncryption) Title() string {
	return "EMR security configuration without in-transit encryption"
}
func (emrNoTransitEncryption) Description() string {
	return "EMR clusters should encrypt data in transit between nodes. The " +
		"security configuration JSON must set EnableInTransitEncryption to true. " +
		"Absent or unparseable configuration is treated as undecidable."
}
func (emrNoTransitEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (emrNoTransitEncryption) AppliesTo(resType string) bool {
	return resType == "aws_emr_security_configuration"
}

func (emrNoTransitEncryption) Check(r ir.Resource) []ir.Finding {
	enc, ok := emrEncryptionConfig(r)
	if !ok {
		return nil // absent/unparseable: cannot decide
	}
	val, present := emrConfigBool(enc, "EnableInTransitEncryption")
	if present && val {
		return nil
	}
	_, span, _, _ := getString(r, "configuration")
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-516",
		Title:       (emrNoTransitEncryption{}).Title(),
		Description: (emrNoTransitEncryption{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "configuration.EncryptionConfiguration.EnableInTransitEncryption",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false or absent",
			Expected:  "EnableInTransitEncryption = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-517: EMR security configuration without at-rest (local disk)
// encryption (Checkov CKV_AWS_349)
// ---------------------------------------------------------------------------

type emrNoLocalDiskEncryption struct{}

func (emrNoLocalDiskEncryption) ID() string { return "AEGIS-AWS-517" }
func (emrNoLocalDiskEncryption) Title() string {
	return "EMR security configuration without local disk encryption"
}
func (emrNoLocalDiskEncryption) Description() string {
	return "EMR clusters should encrypt local disks at rest. The security " +
		"configuration JSON must set EnableAtRestEncryption to true. " +
		"Absent or unparseable configuration is treated as undecidable."
}
func (emrNoLocalDiskEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (emrNoLocalDiskEncryption) AppliesTo(resType string) bool {
	return resType == "aws_emr_security_configuration"
}

func (emrNoLocalDiskEncryption) Check(r ir.Resource) []ir.Finding {
	enc, ok := emrEncryptionConfig(r)
	if !ok {
		return nil // absent/unparseable: cannot decide
	}
	val, present := emrConfigBool(enc, "EnableAtRestEncryption")
	if present && val {
		return nil
	}
	_, span, _, _ := getString(r, "configuration")
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-517",
		Title:       (emrNoLocalDiskEncryption{}).Title(),
		Description: (emrNoLocalDiskEncryption{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "configuration.EncryptionConfiguration.EnableAtRestEncryption",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "false or absent",
			Expected:  "EnableAtRestEncryption = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-518: DAX cluster without TLS encryption (Checkov CKV_AWS_239)
// ---------------------------------------------------------------------------

type daxNoTLS struct{}

func (daxNoTLS) ID() string { return "AEGIS-AWS-518" }
func (daxNoTLS) Title() string {
	return "DAX cluster without TLS encryption"
}
func (daxNoTLS) Description() string {
	return "DAX clusters should use TLS for cluster endpoint encryption " +
		"(cluster_endpoint_encryption_type = TLS). The provider default is " +
		"unencrypted, so an absent value is a finding."
}
func (daxNoTLS) Severity() ir.Severity { return ir.SeverityMedium }

func (daxNoTLS) AppliesTo(resType string) bool {
	return resType == "aws_dax_cluster"
}

func (daxNoTLS) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "cluster_endpoint_encryption_type")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.EqualFold(strings.TrimSpace(val), "TLS") {
		return nil
	}
	actual := "absent (defaults to unencrypted)"
	if present {
		actual = val
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-518",
		Title:       (daxNoTLS{}).Title(),
		Description: (daxNoTLS{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "cluster_endpoint_encryption_type",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "cluster_endpoint_encryption_type = \"TLS\"",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-519: Elasticsearch/OpenSearch domain with outdated TLS policy
// (Checkov CKV_AWS_228)
// ---------------------------------------------------------------------------

type searchOutdatedTLS struct{}

func (searchOutdatedTLS) ID() string { return "AEGIS-AWS-519" }
func (searchOutdatedTLS) Title() string {
	return "Search domain with outdated TLS security policy"
}
func (searchOutdatedTLS) Description() string {
	return "Elasticsearch/OpenSearch domains should require at least TLS 1.2 " +
		"(tls_security_policy of Policy-Min-TLS-1-2-2019-07 or newer). Older " +
		"policies allow TLS 1.0/1.1."
}
func (searchOutdatedTLS) Severity() ir.Severity { return ir.SeverityMedium }

func (searchOutdatedTLS) AppliesTo(resType string) bool {
	return resType == "aws_elasticsearch_domain" || resType == "aws_opensearch_domain"
}

// knownOutdatedSearchPolicies are TLS policies older than
// Policy-Min-TLS-1-2-2019-07. Only these fire; unrecognized policy names
// are treated as undecidable, never as findings.
var knownOutdatedSearchPolicies = map[string]bool{
	"Policy-Min-TLS-1-0-2019-07": true,
}

func (searchOutdatedTLS) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "domain_endpoint_options")
	if !present || !known || len(blks) == 0 {
		return nil // absent/unresolved: provider default is TLS 1.2
	}
	pol, pspan, ppresent, pknown := blockString(blks[0], "tls_security_policy")
	if !ppresent || !pknown {
		return nil // absent/unresolved: cannot decide
	}
	if !knownOutdatedSearchPolicies[strings.TrimSpace(pol)] {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-519",
		Title:       (searchOutdatedTLS{}).Title(),
		Description: (searchOutdatedTLS{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "domain_endpoint_options.tls_security_policy",
			Span:      evidenceSpan(pspan, evidenceSpan(span, r.Span)),
			Actual:    pol,
			Expected:  "tls_security_policy of Policy-Min-TLS-1-2-2019-07 or newer",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-520: Transfer Server with outdated security policy
// (Checkov CKV_AWS_380)
// ---------------------------------------------------------------------------

type transferOldSecurityPolicy struct{}

func (transferOldSecurityPolicy) ID() string { return "AEGIS-AWS-520" }
func (transferOldSecurityPolicy) Title() string {
	return "Transfer Server with outdated security policy"
}
func (transferOldSecurityPolicy) Description() string {
	return "AWS Transfer Family servers should use a security policy of " +
		"TransferSecurityPolicy-2020-06 or newer. Older policies enable weak " +
		"ciphers and key-exchange algorithms."
}
func (transferOldSecurityPolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (transferOldSecurityPolicy) AppliesTo(resType string) bool {
	return resType == "aws_transfer_server"
}

// knownOutdatedTransferPolicies are security policies older than
// TransferSecurityPolicy-2020-06. Only these fire; unrecognized policy
// names are treated as undecidable.
var knownOutdatedTransferPolicies = map[string]bool{
	"TransferSecurityPolicy-2018-11": true,
}

func (transferOldSecurityPolicy) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "security_policy_name")
	if !present || !known {
		return nil // absent/unresolved: provider default is 2020-06
	}
	if !knownOutdatedTransferPolicies[strings.TrimSpace(val)] {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-520",
		Title:       (transferOldSecurityPolicy{}).Title(),
		Description: (transferOldSecurityPolicy{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "security_policy_name",
			Span:      evidenceSpan(span, r.Span),
			Actual:    val,
			Expected:  "security_policy_name of TransferSecurityPolicy-2020-06 or newer",
		},
	}}
}
