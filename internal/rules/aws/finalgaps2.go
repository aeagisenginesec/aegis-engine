package aws

// Final gap rules part 2 (AEGIS-AWS-546–551): RDS/Lambda hygiene plus
// ElastiCache encryption (Checkov parity).
//
// 545, 546, 548, 551 are Hygiene (Low): operational best practices, not
// security vulnerabilities. Descriptions start with "Hygiene:".
// 549, 550 are High severity: real encryption gaps.

import (
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-545: RDS instance without Multi-AZ
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AEGIS-AWS-546: RDS instance without copy_tags_to_snapshot
// ---------------------------------------------------------------------------

type rdsNoCopyTags struct{}

func (rdsNoCopyTags) ID() string { return "AEGIS-AWS-546" }
func (rdsNoCopyTags) Title() string {
	return "RDS instance without copy_tags_to_snapshot"
}
func (rdsNoCopyTags) Description() string {
	return "Hygiene: RDS instances should copy tags to snapshots so " +
		"backup resources inherit cost-allocation and ownership tags. " +
		"Set copy_tags_to_snapshot = true."
}
func (rdsNoCopyTags) Severity() ir.Severity { return ir.SeverityLow }
func (rdsNoCopyTags) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (rdsNoCopyTags) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "copy_tags_to_snapshot")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || !val {
		actual := "absent"
		if present {
			actual = "false"
		}
		return []ir.Finding{hygieneFinding("AEGIS-AWS-546",
			(rdsNoCopyTags{}).Title(), (rdsNoCopyTags{}).Description(),
			r, "copy_tags_to_snapshot", span, actual,
			"copy_tags_to_snapshot = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-547: Lambda function without X-Ray tracing
// ---------------------------------------------------------------------------

type lambdaNoTracing struct{}

func (lambdaNoTracing) ID() string { return "AEGIS-AWS-547" }
func (lambdaNoTracing) Title() string {
	return "Lambda function without X-Ray active tracing"
}
func (lambdaNoTracing) Description() string {
	return "Hygiene: Lambda functions should enable X-Ray active tracing " +
		"for distributed request observability. Add a tracing_config " +
		"block with mode = \"Active\"."
}
func (lambdaNoTracing) Severity() ir.Severity { return ir.SeverityLow }
func (lambdaNoTracing) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}
func (lambdaNoTracing) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "tracing_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-547",
			(lambdaNoTracing{}).Title(), (lambdaNoTracing{}).Description(),
			r, "tracing_config", span, "absent",
			"tracing_config block with mode = \"Active\"")}
	}
	mode, _, mpresent, mknown := blockString(blks[0], "mode")
	if mpresent && !mknown {
		return nil // unresolved: cannot decide
	}
	if !mpresent || !strings.EqualFold(strings.TrimSpace(mode), "Active") {
		actual := "absent"
		if mpresent {
			actual = mode
		}
		return []ir.Finding{hygieneFinding("AEGIS-AWS-547",
			(lambdaNoTracing{}).Title(), (lambdaNoTracing{}).Description(),
			r, "tracing_config.mode", span, actual,
			"tracing_config block with mode = \"Active\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-548: Lambda function without reserved concurrency
// ---------------------------------------------------------------------------

type lambdaNoReservedConcurrency struct{}

func (lambdaNoReservedConcurrency) ID() string { return "AEGIS-AWS-548" }
func (lambdaNoReservedConcurrency) Title() string {
	return "Lambda function without reserved concurrent executions"
}
func (lambdaNoReservedConcurrency) Description() string {
	return "Hygiene: Lambda functions should set " +
		"reserved_concurrent_executions to cap concurrency, preventing " +
		"runaway scaling and unexpected cost. Set the attribute explicitly."
}
func (lambdaNoReservedConcurrency) Severity() ir.Severity { return ir.SeverityLow }
func (lambdaNoReservedConcurrency) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}
func (lambdaNoReservedConcurrency) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attr("reserved_concurrent_executions")
	if !ok {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-548",
			(lambdaNoReservedConcurrency{}).Title(), (lambdaNoReservedConcurrency{}).Description(),
			r, "reserved_concurrent_executions", r.Span, "absent",
			"reserved_concurrent_executions set to an explicit value")}
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-549: ElastiCache replication group without at-rest encryption
// ---------------------------------------------------------------------------

type elasticacheNoAtRest struct{}

func (elasticacheNoAtRest) ID() string { return "AEGIS-AWS-549" }
func (elasticacheNoAtRest) Title() string {
	return "ElastiCache replication group without at-rest encryption"
}
func (elasticacheNoAtRest) Description() string {
	return "ElastiCache replication groups should encrypt data at rest " +
		"to protect cached sensitive data. Set " +
		"at_rest_encryption_enabled = true."
}
func (elasticacheNoAtRest) Severity() ir.Severity { return ir.SeverityHigh }
func (elasticacheNoAtRest) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}
func (elasticacheNoAtRest) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "at_rest_encryption_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || !val {
		actual := "absent"
		if present {
			actual = "false"
		}
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-549",
			Title:       (elasticacheNoAtRest{}).Title(),
			Description: (elasticacheNoAtRest{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "at_rest_encryption_enabled",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "at_rest_encryption_enabled = true",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-550: ElastiCache replication group without transit encryption
// ---------------------------------------------------------------------------

type elasticacheNoTransit struct{}

func (elasticacheNoTransit) ID() string { return "AEGIS-AWS-550" }
func (elasticacheNoTransit) Title() string {
	return "ElastiCache replication group without in-transit encryption"
}
func (elasticacheNoTransit) Description() string {
	return "ElastiCache replication groups should encrypt data in transit " +
		"to protect cached data on the wire. Set " +
		"transit_encryption_enabled = true."
}
func (elasticacheNoTransit) Severity() ir.Severity { return ir.SeverityHigh }
func (elasticacheNoTransit) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}
func (elasticacheNoTransit) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "transit_encryption_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || !val {
		actual := "absent"
		if present {
			actual = "false"
		}
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-550",
			Title:       (elasticacheNoTransit{}).Title(),
			Description: (elasticacheNoTransit{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "transit_encryption_enabled",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "transit_encryption_enabled = true",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-551: ElastiCache replication group without Multi-AZ
// ---------------------------------------------------------------------------

type elasticacheNoMultiAZ struct{}

func (elasticacheNoMultiAZ) ID() string { return "AEGIS-AWS-551" }
func (elasticacheNoMultiAZ) Title() string {
	return "ElastiCache replication group without Multi-AZ / failover"
}
func (elasticacheNoMultiAZ) Description() string {
	return "Hygiene: ElastiCache replication groups should enable " +
		"Multi-AZ with automatic failover for high availability. Set " +
		"multi_az_enabled = true and automatic_failover_enabled = true."
}
func (elasticacheNoMultiAZ) Severity() ir.Severity { return ir.SeverityLow }
func (elasticacheNoMultiAZ) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_replication_group"
}
func (elasticacheNoMultiAZ) Check(r ir.Resource) []ir.Finding {
	multiAZ, _, mpresent, mknown := getBool(r, "multi_az_enabled")
	if mpresent && !mknown {
		return nil // unresolved: cannot decide
	}
	failover, fspan, fpresent, fknown := getBool(r, "automatic_failover_enabled")
	if fpresent && !fknown {
		return nil // unresolved: cannot decide
	}
	multiAZOn := mpresent && multiAZ
	failoverOn := fpresent && failover
	if !multiAZOn && !failoverOn {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-551",
			(elasticacheNoMultiAZ{}).Title(), (elasticacheNoMultiAZ{}).Description(),
			r, "multi_az_enabled/automatic_failover_enabled", fspan,
			"both absent or false",
			"multi_az_enabled = true and automatic_failover_enabled = true")}
	}
	return nil
}

// FinalGap2Rules returns the final gap rules part 2 in ID order (546–551).
func FinalGap2Rules() []ir.Rule {
	return []ir.Rule{
		rdsNoCopyTags{},               // AEGIS-AWS-546
		lambdaNoTracing{},             // AEGIS-AWS-547
		lambdaNoReservedConcurrency{}, // AEGIS-AWS-548
		elasticacheNoAtRest{},         // AEGIS-AWS-549
		elasticacheNoTransit{},        // AEGIS-AWS-550
		elasticacheNoMultiAZ{},        // AEGIS-AWS-551
	}
}
