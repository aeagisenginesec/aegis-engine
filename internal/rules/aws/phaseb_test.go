package aws

import (
	"testing"

	"aegis/internal/ir"
)

// Phase B tests: AEGIS-AWS-860 (EBS snapshot public) and the MSK
// client-broker alignment (AEGIS-AWS-345 / AEGIS-AWS-808) across the
// Terraform attribute, the legacy block key, and the CloudFormation
// nested shape.

// AEGIS-AWS-860: EBS snapshot shared with everyone (group all).

func TestAWS860_SnapshotPublicFires(t *testing.T) {
	r := res("aws_snapshot_create_volume_permission", "snap", map[string]ir.Value{
		"group": ks("all", 2),
	})
	f := runRule(ebsSnapshotPublic{}, r)
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-860" || f[0].Severity != "high" {
		t.Fatalf("expected 1 high AEGIS-AWS-860 finding, got %+v", f)
	}
	if f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("evidence must carry actual and expected: %+v", f[0].Evidence)
	}
}

func TestAWS860_GroupAllCaseInsensitive(t *testing.T) {
	r := res("aws_snapshot_create_volume_permission", "snap", map[string]ir.Value{
		"group": ks("ALL", 2),
	})
	if f := runRule(ebsSnapshotPublic{}, r); len(f) != 1 {
		t.Fatalf("group ALL must fire, got %d", len(f))
	}
}

func TestAWS860_SpecificAccountQuiet(t *testing.T) {
	r := res("aws_snapshot_create_volume_permission", "snap", map[string]ir.Value{
		"group": ks("123456789012", 2),
	})
	if f := runRule(ebsSnapshotPublic{}, r); len(f) != 0 {
		t.Fatalf("specific account group must stay quiet, got %+v", f)
	}
}

func TestAWS860_NoGroupQuiet(t *testing.T) {
	r := res("aws_snapshot_create_volume_permission", "snap", map[string]ir.Value{
		"user_ids": strList(2, "123456789012"),
	})
	if f := runRule(ebsSnapshotPublic{}, r); len(f) != 0 {
		t.Fatalf("permission without group must stay quiet, got %+v", f)
	}
}

// MSK client-broker alignment (P0-4 / P1-5).

func mskCluster(t *testing.T, encInfo ir.Value) ir.Resource {
	t.Helper()
	attrs := map[string]ir.Value{}
	if encInfo.Known || encInfo.Raw != nil {
		attrs["encryption_info"] = encInfo
	}
	return res("aws_msk_cluster", "main", attrs)
}

func TestMSK345_PlaintextFires(t *testing.T) {
	// Terraform attribute form.
	r := mskCluster(t, blks(2, blk("encryption_in_transit_client_broker", ks("PLAINTEXT", 3))))
	if f := runRule(mskNoEncryption{}, r); len(f) != 1 {
		t.Fatalf("TF attribute PLAINTEXT must fire 345, got %+v", f)
	}
	// Legacy block key form.
	r = mskCluster(t, blks(2, blk("client_broker", ks("PLAINTEXT", 3))))
	if f := runRule(mskNoEncryption{}, r); len(f) != 1 {
		t.Fatalf("client_broker PLAINTEXT must fire 345, got %+v", f)
	}
	// CloudFormation nested form: encryption_in_transit.client_broker.
	nested := ir.Value{Raw: map[string]ir.Value{"client_broker": ks("PLAINTEXT", 3)}, Known: true, Span: spanAt(3)}
	r = mskCluster(t, blks(2, blk("encryption_in_transit", nested)))
	if f := runRule(mskNoEncryption{}, r); len(f) != 1 {
		t.Fatalf("CFN nested PLAINTEXT must fire 345, got %+v", f)
	}
	// Case-insensitive.
	r = mskCluster(t, blks(2, blk("client_broker", ks("plaintext", 3))))
	if f := runRule(mskNoEncryption{}, r); len(f) != 1 {
		t.Fatalf("lowercase plaintext must fire 345, got %+v", f)
	}
}

func TestMSK345_TLSQuiet(t *testing.T) {
	r := mskCluster(t, blks(2, blk("client_broker", ks("TLS", 3))))
	if f := runRule(mskNoEncryption{}, r); len(f) != 0 {
		t.Fatalf("TLS must stay quiet for 345, got %+v", f)
	}
	r = mskCluster(t, blks(2, blk("encryption_in_transit_client_broker", ks("TLS_PLAINTEXT", 3))))
	if f := runRule(mskNoEncryption{}, r); len(f) != 0 {
		t.Fatalf("TLS_PLAINTEXT must stay quiet for 345, got %+v", f)
	}
}

func TestMSK808_PlaintextFires(t *testing.T) {
	r := mskCluster(t, blks(2, blk("encryption_in_transit_client_broker", ks("PLAINTEXT", 3))))
	if f := runRule(mskPlaintextBrokers{}, r); len(f) != 1 {
		t.Fatalf("TF attribute PLAINTEXT must fire 808, got %+v", f)
	}
	nested := ir.Value{Raw: map[string]ir.Value{"client_broker": ks("PLAINTEXT", 3)}, Known: true, Span: spanAt(3)}
	r = mskCluster(t, blks(2, blk("encryption_in_transit", nested)))
	if f := runRule(mskPlaintextBrokers{}, r); len(f) != 1 {
		t.Fatalf("CFN nested PLAINTEXT must fire 808, got %+v", f)
	}
}

func TestMSK808_TLSQuiet(t *testing.T) {
	r := mskCluster(t, blks(2, blk("client_broker", ks("TLS", 3))))
	if f := runRule(mskPlaintextBrokers{}, r); len(f) != 0 {
		t.Fatalf("TLS must stay quiet for 808, got %+v", f)
	}
	// Absent encryption_info: provider default is TLS_PLAINTEXT.
	r = mskCluster(t, ir.Value{})
	if f := runRule(mskPlaintextBrokers{}, r); len(f) != 0 {
		t.Fatalf("absent encryption_info must stay quiet for 808, got %+v", f)
	}
}
