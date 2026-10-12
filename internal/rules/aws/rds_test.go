package aws

import (
	"testing"

	"aegis/internal/ir"
)

// AEGIS-AWS-007: RDS instance without storage encryption.

func TestRDSUnencrypted_AbsentFires(t *testing.T) {
	db := res("aws_db_instance", "main", nil)
	f := runRule(rdsUnencrypted{}, db)
	if len(f) != 1 || f[0].Severity != "high" {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "storage_encrypted" {
		t.Fatalf("wrong evidence attribute: %s", f[0].Evidence.Attribute)
	}
}

func TestRDSUnencrypted_FalseFires(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{"storage_encrypted": kv(false, 3)})
	f := runRule(rdsUnencrypted{}, db)
	if len(f) != 1 || f[0].Evidence.Actual != "false" {
		t.Fatalf("expected 1 finding with Actual=false, got %+v", f)
	}
}

func TestRDSUnencrypted_TrueOK(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{"storage_encrypted": kv(true, 3)})
	if f := runRule(rdsUnencrypted{}, db); len(f) != 0 {
		t.Fatalf("encrypted RDS must not fire, got %d", len(f))
	}
}

func TestRDSUnencrypted_UnknownNoFinding(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{"storage_encrypted": ku(3)})
	if f := runRule(rdsUnencrypted{}, db); len(f) != 0 {
		t.Fatalf("unknown storage_encrypted must not fire, got %d", len(f))
	}
}

// AEGIS-AWS-008: RDS instance without deletion protection.

func TestRDSNoDeletionProtection_AbsentFires(t *testing.T) {
	db := res("aws_db_instance", "main", nil)
	f := runRule(rdsNoDeletionProtection{}, db)
	if len(f) != 1 || f[0].Severity != "medium" {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
}

func TestRDSNoDeletionProtection_TrueOK(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{"deletion_protection": kv(true, 3)})
	if f := runRule(rdsNoDeletionProtection{}, db); len(f) != 0 {
		t.Fatalf("protected RDS must not fire, got %d", len(f))
	}
}

func TestRDSNoDeletionProtection_UnknownNoFinding(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{"deletion_protection": ku(3)})
	if f := runRule(rdsNoDeletionProtection{}, db); len(f) != 0 {
		t.Fatalf("unknown deletion_protection must not fire, got %d", len(f))
	}
}

// AEGIS-AWS-011: RDS instance publicly accessible.

func TestRDSPublic_TrueFires(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{"publicly_accessible": kv(true, 3)})
	f := runRule(rdsPublic{}, db)
	if len(f) != 1 || f[0].Severity != "high" {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "publicly_accessible" || f[0].Evidence.Actual != "true" {
		t.Fatalf("wrong evidence: %+v", f[0].Evidence)
	}
}

func TestRDSPublic_AbsentOrFalseOK(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		nil,
		{"publicly_accessible": kv(false, 3)},
	} {
		db := res("aws_db_instance", "main", attrs)
		if f := runRule(rdsPublic{}, db); len(f) != 0 {
			t.Fatalf("absent/false publicly_accessible must not fire, got %d", len(f))
		}
	}
}

func TestRDSPublic_UnknownNoFinding(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{"publicly_accessible": ku(3)})
	if f := runRule(rdsPublic{}, db); len(f) != 0 {
		t.Fatalf("unknown publicly_accessible must not fire, got %d", len(f))
	}
}
