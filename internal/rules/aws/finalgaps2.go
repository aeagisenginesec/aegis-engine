package aws

// Final gap rules part 2 (AEGIS-AWS-546–551): RDS/Lambda hygiene plus
// ElastiCache encryption (Checkov parity).
//
// 545, 546, 548, 551 are Hygiene (Low): operational best practices, not
// security vulnerabilities. Descriptions start with "Hygiene:".
// 549, 550 are High severity: real encryption gaps.

import (
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
// AEGIS-AWS-547: Lambda function without X-Ray active tracing

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
		lambdaNoReservedConcurrency{}, // AEGIS-AWS-548
		elasticacheNoMultiAZ{},        // AEGIS-AWS-551
	}
}
