package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-546: RDS instance without copy_tags_to_snapshot
// ---------------------------------------------------------------------------

func Test546_FiresWhenAbsent(t *testing.T) {
	r := res("aws_db_instance", "db", map[string]ir.Value{})
	if fs := runRule(rdsNoCopyTags{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test546_FiresWhenFalse(t *testing.T) {
	r := res("aws_db_instance", "db", map[string]ir.Value{
		"copy_tags_to_snapshot": kv(false, 3),
	})
	if fs := runRule(rdsNoCopyTags{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test546_SilentWhenTrue(t *testing.T) {
	r := res("aws_db_instance", "db", map[string]ir.Value{
		"copy_tags_to_snapshot": kv(true, 3),
	})
	if fs := runRule(rdsNoCopyTags{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-547: Lambda function without X-Ray tracing
// ---------------------------------------------------------------------------

func Test547_FiresWhenAbsent(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{})
	if fs := runRule(lambdaNoTracing{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test547_FiresWhenPassThrough(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"tracing_config": blks(3, blk("mode", ks("PassThrough", 4))),
	})
	if fs := runRule(lambdaNoTracing{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test547_SilentWhenActive(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"tracing_config": blks(3, blk("mode", ks("Active", 4))),
	})
	if fs := runRule(lambdaNoTracing{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-548: Lambda function without reserved concurrency
// ---------------------------------------------------------------------------

func Test548_FiresWhenAbsent(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{})
	if fs := runRule(lambdaNoReservedConcurrency{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test548_SilentWhenSet(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"reserved_concurrent_executions": {Raw: float64(10), Known: true, Span: spanAt(3)},
	})
	if fs := runRule(lambdaNoReservedConcurrency{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test548_SilentWhenUnknown(t *testing.T) {
	r := res("aws_lambda_function", "fn", map[string]ir.Value{
		"reserved_concurrent_executions": ku(3),
	})
	if fs := runRule(lambdaNoReservedConcurrency{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-549: ElastiCache without at-rest encryption
// ---------------------------------------------------------------------------

func Test321_FiresWhenAbsent(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{})
	fs := runRule(elasticacheNoAtRestEnc{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected High severity, got %v", fs[0].Severity)
	}
}

func Test549_FiresWhenFalse(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"at_rest_encryption_enabled": kv(false, 3),
	})
	if fs := runRule(elasticacheNoAtRestEnc{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test549_SilentWhenTrue(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"at_rest_encryption_enabled": kv(true, 3),
	})
	if fs := runRule(elasticacheNoAtRestEnc{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-320: ElastiCache without transit encryption
// ---------------------------------------------------------------------------

func Test320_FiresWhenAbsent(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{})
	fs := runRule(elasticacheNoTransitEnc{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected High severity, got %v", fs[0].Severity)
	}
}

func Test550_FiresWhenFalse(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"transit_encryption_enabled": kv(false, 3),
	})
	if fs := runRule(elasticacheNoTransitEnc{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test550_SilentWhenTrue(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"transit_encryption_enabled": kv(true, 3),
	})
	if fs := runRule(elasticacheNoTransitEnc{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-551: ElastiCache without Multi-AZ / failover
// ---------------------------------------------------------------------------

func Test551_FiresWhenBothAbsent(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{})
	if fs := runRule(elasticacheNoMultiAZ{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test551_FiresWhenBothFalse(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"multi_az_enabled":           kv(false, 3),
		"automatic_failover_enabled": kv(false, 4),
	})
	if fs := runRule(elasticacheNoMultiAZ{}, r); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

func Test551_SilentWhenMultiAZTrue(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"multi_az_enabled": kv(true, 3),
	})
	if fs := runRule(elasticacheNoMultiAZ{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test551_SilentWhenFailoverTrue(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"automatic_failover_enabled": kv(true, 4),
	})
	if fs := runRule(elasticacheNoMultiAZ{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

func Test551_SilentWhenUnknown(t *testing.T) {
	r := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"multi_az_enabled":           ku(3),
		"automatic_failover_enabled": ku(4),
	})
	if fs := runRule(elasticacheNoMultiAZ{}, r); len(fs) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(fs))
	}
}

// ---------------------------------------------------------------------------
// ID order guard
// ---------------------------------------------------------------------------

func TestFinalGap2_InIDOrder(t *testing.T) {
	rules := FinalGap2Rules()
	// 549, 550 removed as post-audit duplicates of 321, 320.
	want := []string{
		"AEGIS-AWS-546", "AEGIS-AWS-547", "AEGIS-AWS-548",
		"AEGIS-AWS-551",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Fatalf("rule %d: expected %s, got %s", i, want[i], r.ID())
		}
	}
}
