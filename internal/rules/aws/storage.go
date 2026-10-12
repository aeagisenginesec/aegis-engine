package aws

import (
	"aegis/internal/ir"
)

// StorageRules returns the storage & database rules, AEGIS-AWS-311..322,
// in ID order.
func StorageRules() []ir.Rule {
	return []ir.Rule{
		rdsNoIAMAuth{},              // AEGIS-AWS-311
		dynamoNoPITR{},              // AEGIS-AWS-312
		dynamoNoCMK{},               // AEGIS-AWS-313
		redshiftUnencrypted{},       // AEGIS-AWS-314
		redshiftPublic{},            // AEGIS-AWS-315
		redshiftNoAuditLog{},        // AEGIS-AWS-316
		efsUnencrypted{},            // AEGIS-AWS-317
		opensearchNoNodeToNode{},    // AEGIS-AWS-318
		opensearchNoEncryptAtRest{}, // AEGIS-AWS-319
		elasticacheNoTransitEnc{},   // AEGIS-AWS-320
		elasticacheNoAtRestEnc{},    // AEGIS-AWS-321
		auroraNoBackup{},            // AEGIS-AWS-322
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-311: RDS without IAM database authentication
// ---------------------------------------------------------------------------

type rdsNoIAMAuth struct{}

func (rdsNoIAMAuth) ID() string { return "AEGIS-AWS-311" }
func (rdsNoIAMAuth) Title() string {
	return "RDS without IAM database authentication"
}
func (rdsNoIAMAuth) Description() string {
	return "With iam_database_authentication_enabled absent or false, database " +
		"access relies on long-lived passwords instead of short-lived IAM " +
		"credentials, weakening credential hygiene."
}
func (rdsNoIAMAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (rdsNoIAMAuth) AppliesTo(resType string) bool { return resType == "aws_db_instance" }

func (rdsNoIAMAuth) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "iam_database_authentication_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && en {
		return nil
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-311",
		Title:       (rdsNoIAMAuth{}).Title(),
		Description: (rdsNoIAMAuth{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "iam_database_authentication_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "iam_database_authentication_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-312: DynamoDB table without point-in-time recovery
// ---------------------------------------------------------------------------

type dynamoNoPITR struct{}

func (dynamoNoPITR) ID() string { return "AEGIS-AWS-312" }
func (dynamoNoPITR) Title() string {
	return "DynamoDB table without point-in-time recovery"
}
func (dynamoNoPITR) Description() string {
	return "Without a point_in_time_recovery block, DynamoDB continuous backups " +
		"are disabled and the table cannot be restored to an arbitrary point " +
		"in the preceding 35 days."
}
func (dynamoNoPITR) Severity() ir.Severity { return ir.SeverityMedium }

func (dynamoNoPITR) AppliesTo(resType string) bool { return resType == "aws_dynamodb_table" }

func (dynamoNoPITR) Check(r ir.Resource) []ir.Finding {
	return nestedEnabledCheck(r, "point_in_time_recovery", "AEGIS-AWS-312",
		(dynamoNoPITR{}).Title(), (dynamoNoPITR{}).Description(), ir.SeverityMedium,
		"absent (provider default: disabled)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-313: DynamoDB table without customer-managed encryption
// ---------------------------------------------------------------------------

type dynamoNoCMK struct{}

func (dynamoNoCMK) ID() string { return "AEGIS-AWS-313" }
func (dynamoNoCMK) Title() string {
	return "DynamoDB table without customer-managed encryption"
}
func (dynamoNoCMK) Description() string {
	return "AWS encrypts DynamoDB tables at rest by default with AWS-owned keys; " +
		"this rule treats a missing server_side_encryption block as insufficient " +
		"because AWS-owned keys offer no customer control over key rotation or " +
		"revocation. Set server_side_encryption { enabled = true, kms_key_arn = ... }."
}
func (dynamoNoCMK) Severity() ir.Severity { return ir.SeverityHigh }

func (dynamoNoCMK) AppliesTo(resType string) bool { return resType == "aws_dynamodb_table" }

func (dynamoNoCMK) Check(r ir.Resource) []ir.Finding {
	return nestedEnabledCheck(r, "server_side_encryption", "AEGIS-AWS-313",
		(dynamoNoCMK{}).Title(), (dynamoNoCMK{}).Description(), ir.SeverityHigh,
		"absent (AWS-owned key, no customer control)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-314: Redshift cluster unencrypted
// ---------------------------------------------------------------------------

type redshiftUnencrypted struct{}

func (redshiftUnencrypted) ID() string { return "AEGIS-AWS-314" }
func (redshiftUnencrypted) Title() string {
	return "Redshift cluster unencrypted"
}
func (redshiftUnencrypted) Description() string {
	return "Redshift clusters are unencrypted unless encrypted = true; " +
		"unencrypted clusters expose data at rest on cluster storage."
}
func (redshiftUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (redshiftUnencrypted) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}

func (redshiftUnencrypted) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "encrypted")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && en {
		return nil
	}
	actual := "absent (provider default: unencrypted)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-314",
		Title:       (redshiftUnencrypted{}).Title(),
		Description: (redshiftUnencrypted{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "encrypted = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-315: Redshift cluster publicly accessible
// ---------------------------------------------------------------------------

type redshiftPublic struct{}

func (redshiftPublic) ID() string { return "AEGIS-AWS-315" }
func (redshiftPublic) Title() string {
	return "Redshift cluster publicly accessible"
}
func (redshiftPublic) Description() string {
	return "A publicly_accessible Redshift cluster accepts connections from " +
		"the internet, exposing the data warehouse to network attacks."
}
func (redshiftPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (redshiftPublic) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}

func (redshiftPublic) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "publicly_accessible")
	if !present || !known {
		return nil // default is false; unresolved: cannot decide
	}
	if !pub {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-315",
		Title:       (redshiftPublic{}).Title(),
		Description: (redshiftPublic{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "publicly_accessible",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "publicly_accessible = false (or omitted)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-316: Redshift cluster without audit logging
// ---------------------------------------------------------------------------

type redshiftNoAuditLog struct{}

func (redshiftNoAuditLog) ID() string { return "AEGIS-AWS-316" }
func (redshiftNoAuditLog) Title() string {
	return "Redshift cluster without audit logging"
}
func (redshiftNoAuditLog) Description() string {
	return "Without a logging block, Redshift audit logs are not delivered " +
		"to S3, leaving connection and query activity unrecorded for " +
		"forensics and compliance."
}
func (redshiftNoAuditLog) Severity() ir.Severity { return ir.SeverityMedium }

func (redshiftNoAuditLog) AppliesTo(resType string) bool {
	return resType == "aws_redshift_cluster"
}

func (redshiftNoAuditLog) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "logging")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil // logging configured
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-316",
		Title:       (redshiftNoAuditLog{}).Title(),
		Description: (redshiftNoAuditLog{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "logging",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent (audit logging disabled)",
			Expected:  "logging { bucket_name = ... }",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-317: EFS file system unencrypted
// ---------------------------------------------------------------------------

type efsUnencrypted struct{}

func (efsUnencrypted) ID() string { return "AEGIS-AWS-317" }
func (efsUnencrypted) Title() string {
	return "EFS file system unencrypted"
}
func (efsUnencrypted) Description() string {
	return "EFS file systems are unencrypted unless encrypted = true; " +
		"unencrypted file systems expose data at rest."
}
func (efsUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (efsUnencrypted) AppliesTo(resType string) bool { return resType == "aws_efs_file_system" }

func (efsUnencrypted) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "encrypted")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && en {
		return nil
	}
	actual := "absent (provider default: unencrypted)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-317",
		Title:       (efsUnencrypted{}).Title(),
		Description: (efsUnencrypted{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "encrypted = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-318: OpenSearch domain without node-to-node encryption
// ---------------------------------------------------------------------------

type opensearchNoNodeToNode struct{}

func (opensearchNoNodeToNode) ID() string { return "AEGIS-AWS-318" }
func (opensearchNoNodeToNode) Title() string {
	return "OpenSearch domain without node-to-node encryption"
}
func (opensearchNoNodeToNode) Description() string {
	return "Without node_to_node_encryption { enabled = true }, traffic " +
		"between cluster nodes is unencrypted and observable on the network."
}
func (opensearchNoNodeToNode) Severity() ir.Severity { return ir.SeverityHigh }

func (opensearchNoNodeToNode) AppliesTo(resType string) bool {
	return resType == "aws_opensearch_domain" || resType == "aws_elasticsearch_domain"
}

func (opensearchNoNodeToNode) Check(r ir.Resource) []ir.Finding {
	return nestedEnabledCheck(r, "node_to_node_encryption", "AEGIS-AWS-318",
		(opensearchNoNodeToNode{}).Title(), (opensearchNoNodeToNode{}).Description(),
		ir.SeverityHigh, "absent (provider default: disabled)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-319: OpenSearch domain without encryption at rest
// ---------------------------------------------------------------------------

type opensearchNoEncryptAtRest struct{}

func (opensearchNoEncryptAtRest) ID() string { return "AEGIS-AWS-319" }
func (opensearchNoEncryptAtRest) Title() string {
	return "OpenSearch domain without encryption at rest"
}
func (opensearchNoEncryptAtRest) Description() string {
	return "Without encrypt_at_rest { enabled = true }, indexed data is " +
		"stored unencrypted on domain volumes."
}
func (opensearchNoEncryptAtRest) Severity() ir.Severity { return ir.SeverityHigh }

func (opensearchNoEncryptAtRest) AppliesTo(resType string) bool {
	return resType == "aws_opensearch_domain" || resType == "aws_elasticsearch_domain"
}

func (opensearchNoEncryptAtRest) Check(r ir.Resource) []ir.Finding {
	return nestedEnabledCheck(r, "encrypt_at_rest", "AEGIS-AWS-319",
		(opensearchNoEncryptAtRest{}).Title(), (opensearchNoEncryptAtRest{}).Description(),
		ir.SeverityHigh, "absent (provider default: disabled)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-320: ElastiCache replication group without transit encryption
// ---------------------------------------------------------------------------

type elasticacheNoTransitEnc struct{}

func (elasticacheNoTransitEnc) ID() string { return "AEGIS-AWS-320" }
func (elasticacheNoTransitEnc) Title() string {
	return "ElastiCache replication group without transit encryption"
}
func (elasticacheNoTransitEnc) Description() string {
	return "With transit_encryption_enabled absent or false, data in transit " +
		"between the application and the cache is unencrypted."
}
func (elasticacheNoTransitEnc) Severity() ir.Severity { return ir.SeverityHigh }

func (elasticacheNoTransitEnc) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}

func (elasticacheNoTransitEnc) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "transit_encryption_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && en {
		return nil
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-320",
		Title:       (elasticacheNoTransitEnc{}).Title(),
		Description: (elasticacheNoTransitEnc{}).Description(),
		Severity:    (elasticacheNoTransitEnc{}).Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "transit_encryption_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "transit_encryption_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-321: ElastiCache replication group without at-rest encryption
// ---------------------------------------------------------------------------

type elasticacheNoAtRestEnc struct{}

func (elasticacheNoAtRestEnc) ID() string { return "AEGIS-AWS-321" }
func (elasticacheNoAtRestEnc) Title() string {
	return "ElastiCache replication group without at-rest encryption"
}
func (elasticacheNoAtRestEnc) Description() string {
	return "With at_rest_encryption_enabled absent or false, cached data " +
		"and snapshots are stored unencrypted."
}
func (elasticacheNoAtRestEnc) Severity() ir.Severity { return ir.SeverityHigh }

func (elasticacheNoAtRestEnc) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}

func (elasticacheNoAtRestEnc) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "at_rest_encryption_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && en {
		return nil
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-321",
		Title:       (elasticacheNoAtRestEnc{}).Title(),
		Description: (elasticacheNoAtRestEnc{}).Description(),
		Severity:    (elasticacheNoAtRestEnc{}).Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "at_rest_encryption_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "at_rest_encryption_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-322: Aurora cluster without backup retention
// ---------------------------------------------------------------------------

type auroraNoBackup struct{}

func (auroraNoBackup) ID() string { return "AEGIS-AWS-322" }
func (auroraNoBackup) Title() string {
	return "Aurora cluster without backup retention"
}
func (auroraNoBackup) Description() string {
	return "With backup_retention_period absent or 0, automated backups are " +
		"disabled and the Aurora cluster cannot be restored after data loss."
}
func (auroraNoBackup) Severity() ir.Severity { return ir.SeverityMedium }

func (auroraNoBackup) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoBackup) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNumber(r, "backup_retention_period")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && days > 0 {
		return nil
	}
	actual := "absent (provider default: no backups)"
	if present {
		actual = "0"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-322",
		Title:       (auroraNoBackup{}).Title(),
		Description: (auroraNoBackup{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "backup_retention_period",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "backup_retention_period > 0 (e.g. 7)",
		},
	}}
}

// nestedEnabledCheck implements the common nested-block-with-enabled-flag
// pattern used by 312, 313, 318, 319: the block absent means the feature is
// off (finding); the block present with enabled known false means off
// (finding); enabled known true means on (no finding); anything unresolved
// or absent-within-block means cannot decide (no finding).
func nestedEnabledCheck(r ir.Resource, blockName, ruleID, title, description string, sev ir.Severity, absentActual string) []ir.Finding {
	blks, span, present, known := getBlocks(r, blockName)
	if present && !known {
		return nil // unresolved block: cannot decide
	}
	mk := func(actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      ruleID,
			Title:       title,
			Description: description,
			Severity:    sev,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: blockName + ".enabled",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  blockName + " { enabled = true }",
			},
		}}
	}
	if !present || len(blks) == 0 {
		return mk(absentActual)
	}
	for _, b := range blks {
		en, _, epresent, eknown := blockBool(b, "enabled")
		if epresent && !eknown {
			return nil // unresolved: cannot decide
		}
		if epresent && !en {
			return mk("false")
		}
		if epresent && en {
			return nil
		}
	}
	// Block present but enabled absent everywhere: cannot decide.
	return nil
}
