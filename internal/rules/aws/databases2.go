package aws

import (
	"strings"

	"aegis/internal/ir"
)

// Databases2Rules returns the database extras rules, AEGIS-AWS-351..360,
// in ID order.
func Databases2Rules() []ir.Rule {
	return []ir.Rule{
		docdbUnencrypted{},      // AEGIS-AWS-351
		neptuneUnencrypted{},    // AEGIS-AWS-352
		docdbNoBackup{},         // AEGIS-AWS-353
		memorydbNoTLS{},         // AEGIS-AWS-354
		daxNoEncryption{},       // AEGIS-AWS-355
		dmsPublic{},             // AEGIS-AWS-356
		dmsNoSSL{},              // AEGIS-AWS-357
		auroraNoDelProtection{}, // AEGIS-AWS-358
		auroraUnencrypted{},     // AEGIS-AWS-359
		auroraNoIAMAuth{},       // AEGIS-AWS-360
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-351: DocumentDB cluster unencrypted
// ---------------------------------------------------------------------------

type docdbUnencrypted struct{}

func (docdbUnencrypted) ID() string { return "AEGIS-AWS-351" }
func (docdbUnencrypted) Title() string {
	return "DocumentDB cluster unencrypted"
}
func (docdbUnencrypted) Description() string {
	return "DocumentDB clusters are unencrypted unless storage_encrypted = true; " +
		"unencrypted clusters expose data at rest."
}
func (docdbUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (docdbUnencrypted) AppliesTo(resType string) bool { return resType == "aws_docdb_cluster" }

func (docdbUnencrypted) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "storage_encrypted")
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
		RuleID:      "AEGIS-AWS-351",
		Title:       (docdbUnencrypted{}).Title(),
		Description: (docdbUnencrypted{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "storage_encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "storage_encrypted = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-352: Neptune cluster unencrypted
// ---------------------------------------------------------------------------

type neptuneUnencrypted struct{}

func (neptuneUnencrypted) ID() string { return "AEGIS-AWS-352" }
func (neptuneUnencrypted) Title() string {
	return "Neptune cluster unencrypted"
}
func (neptuneUnencrypted) Description() string {
	return "Neptune clusters are unencrypted unless storage_encrypted = true; " +
		"unencrypted clusters expose graph data at rest."
}
func (neptuneUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (neptuneUnencrypted) AppliesTo(resType string) bool { return resType == "aws_neptune_cluster" }

func (neptuneUnencrypted) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "storage_encrypted")
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
		RuleID:      "AEGIS-AWS-352",
		Title:       (neptuneUnencrypted{}).Title(),
		Description: (neptuneUnencrypted{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "storage_encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "storage_encrypted = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-353: DocumentDB cluster without backup retention
// ---------------------------------------------------------------------------

type docdbNoBackup struct{}

func (docdbNoBackup) ID() string { return "AEGIS-AWS-353" }
func (docdbNoBackup) Title() string {
	return "DocumentDB cluster without backup retention"
}
func (docdbNoBackup) Description() string {
	return "With backup_retention_period absent or 0, no automated backups " +
		"are kept and point-in-time recovery is impossible."
}
func (docdbNoBackup) Severity() ir.Severity { return ir.SeverityMedium }

func (docdbNoBackup) AppliesTo(resType string) bool { return resType == "aws_docdb_cluster" }

func (docdbNoBackup) Check(r ir.Resource) []ir.Finding {
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
		RuleID:      "AEGIS-AWS-353",
		Title:       (docdbNoBackup{}).Title(),
		Description: (docdbNoBackup{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "backup_retention_period",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "backup_retention_period >= 1",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-354: MemoryDB cluster without TLS
// ---------------------------------------------------------------------------

type memorydbNoTLS struct{}

func (memorydbNoTLS) ID() string { return "AEGIS-AWS-354" }
func (memorydbNoTLS) Title() string {
	return "MemoryDB cluster without TLS"
}
func (memorydbNoTLS) Description() string {
	return "MemoryDB clusters should enforce in-transit encryption with " +
		"tls_enabled = true; without it, client traffic is plaintext."
}
func (memorydbNoTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (memorydbNoTLS) AppliesTo(resType string) bool { return resType == "aws_memorydb_cluster" }

func (memorydbNoTLS) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "tls_enabled")
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
		RuleID:      "AEGIS-AWS-354",
		Title:       (memorydbNoTLS{}).Title(),
		Description: (memorydbNoTLS{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "tls_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "tls_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-355: DAX cluster without encryption
// ---------------------------------------------------------------------------

type daxNoEncryption struct{}

func (daxNoEncryption) ID() string { return "AEGIS-AWS-355" }
func (daxNoEncryption) Title() string {
	return "DAX cluster without encryption"
}
func (daxNoEncryption) Description() string {
	return "DAX clusters should enable server-side encryption; without a " +
		"server_side_encryption block with enabled = true, cached data " +
		"rests unencrypted."
}
func (daxNoEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (daxNoEncryption) AppliesTo(resType string) bool { return resType == "aws_dax_cluster" }

func (daxNoEncryption) Check(r ir.Resource) []ir.Finding {
	return nestedEnabledCheck(r, "server_side_encryption", "AEGIS-AWS-355",
		(daxNoEncryption{}).Title(), (daxNoEncryption{}).Description(), ir.SeverityMedium,
		"absent (provider default: disabled)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-356: DMS replication instance publicly accessible
// ---------------------------------------------------------------------------

type dmsPublic struct{}

func (dmsPublic) ID() string { return "AEGIS-AWS-356" }
func (dmsPublic) Title() string {
	return "DMS replication instance publicly accessible"
}
func (dmsPublic) Description() string {
	return "A DMS replication instance with publicly_accessible = true is " +
		"reachable from the internet, exposing migration traffic and " +
		"endpoint credentials to network attack."
}
func (dmsPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (dmsPublic) AppliesTo(resType string) bool {
	return resType == "aws_dms_replication_instance"
}

func (dmsPublic) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "publicly_accessible")
	if !present || !known || !pub {
		return nil // absent/false/unresolved: no public exposure proven
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-356",
		Title:       (dmsPublic{}).Title(),
		Description: (dmsPublic{}).Description(),
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
// AEGIS-AWS-357: DMS endpoint without SSL
// ---------------------------------------------------------------------------

type dmsNoSSL struct{}

func (dmsNoSSL) ID() string { return "AEGIS-AWS-357" }
func (dmsNoSSL) Title() string {
	return "DMS endpoint without SSL"
}
func (dmsNoSSL) Description() string {
	return "A DMS endpoint with ssl_mode = \"none\" transfers data and " +
		"credentials in plaintext between the replication instance and " +
		"the database endpoint."
}
func (dmsNoSSL) Severity() ir.Severity { return ir.SeverityHigh }

func (dmsNoSSL) AppliesTo(resType string) bool { return resType == "aws_dms_endpoint" }

func (dmsNoSSL) Check(r ir.Resource) []ir.Finding {
	mode, span, present, known := getString(r, "ssl_mode")
	if !present {
		// Optional; the AWS API default is "none": data and credentials
		// travel in plaintext.
		return absentInsecureDefault(dmsNoSSL{}, r,
			"ssl_mode", "absent (provider default: none)",
			"require (or verify-ca / verify-full)")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if strings.ToLower(strings.TrimSpace(mode)) != "none" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-357",
		Title:       (dmsNoSSL{}).Title(),
		Description: (dmsNoSSL{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "ssl_mode",
			Span:      evidenceSpan(span, r.Span),
			Actual:    mode,
			Expected:  "require (or verify-ca / verify-full)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-358: Aurora cluster without deletion protection
// ---------------------------------------------------------------------------

type auroraNoDelProtection struct{}

func (auroraNoDelProtection) ID() string { return "AEGIS-AWS-358" }
func (auroraNoDelProtection) Title() string {
	return "Aurora cluster without deletion protection"
}
func (auroraNoDelProtection) Description() string {
	return "An Aurora cluster without deletion_protection can be destroyed " +
		"by a single API call or Terraform change, with no safety catch."
}
func (auroraNoDelProtection) Severity() ir.Severity { return ir.SeverityMedium }

func (auroraNoDelProtection) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoDelProtection) Check(r ir.Resource) []ir.Finding {
	prot, span, present, known := getBool(r, "deletion_protection")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && prot {
		return nil
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-358",
		Title:       (auroraNoDelProtection{}).Title(),
		Description: (auroraNoDelProtection{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "deletion_protection",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "deletion_protection = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-359: Aurora cluster unencrypted
// ---------------------------------------------------------------------------

type auroraUnencrypted struct{}

func (auroraUnencrypted) ID() string { return "AEGIS-AWS-359" }
func (auroraUnencrypted) Title() string {
	return "Aurora cluster unencrypted"
}
func (auroraUnencrypted) Description() string {
	return "Aurora clusters are unencrypted unless storage_encrypted = true; " +
		"unencrypted clusters expose data at rest."
}
func (auroraUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (auroraUnencrypted) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraUnencrypted) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "storage_encrypted")
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
		RuleID:      "AEGIS-AWS-359",
		Title:       (auroraUnencrypted{}).Title(),
		Description: (auroraUnencrypted{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "storage_encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "storage_encrypted = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-360: Aurora cluster without IAM authentication
// ---------------------------------------------------------------------------

type auroraNoIAMAuth struct{}

func (auroraNoIAMAuth) ID() string { return "AEGIS-AWS-360" }
func (auroraNoIAMAuth) Title() string {
	return "Aurora cluster without IAM authentication"
}
func (auroraNoIAMAuth) Description() string {
	return "With iam_database_authentication_enabled absent or false, Aurora " +
		"access relies on long-lived passwords instead of short-lived IAM " +
		"credentials, weakening credential hygiene."
}
func (auroraNoIAMAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (auroraNoIAMAuth) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoIAMAuth) Check(r ir.Resource) []ir.Finding {
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
		RuleID:      "AEGIS-AWS-360",
		Title:       (auroraNoIAMAuth{}).Title(),
		Description: (auroraNoIAMAuth{}).Description(),
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
