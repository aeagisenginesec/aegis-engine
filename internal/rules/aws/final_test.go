package aws

// Rule IDs covered in this file: AEGIS-AWS-431, AEGIS-AWS-433, AEGIS-AWS-436, AEGIS-AWS-441

import (
	"fmt"
	"testing"

	"aegis/internal/ir"
)

const publicPolicyDoc = `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}`
const restrictedPolicyDoc = `{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "s3:GetObject", "Resource": "*"}]}`

func Test431_PublicFires(t *testing.T) {
	f := runRule(redshiftServerlessPublic{}, res("aws_redshiftserverless_workgroup", "main",
		map[string]ir.Value{"publicly_accessible": kv(true, 3)}))
	if len(f) != 1 || f[0].Severity != ir.SeverityHigh {
		t.Fatalf("want 1 high finding, got %+v", f)
	}
}

func Test431_PrivateQuiet(t *testing.T) {
	f := runRule(redshiftServerlessPublic{}, res("aws_redshiftserverless_workgroup", "main",
		map[string]ir.Value{"publicly_accessible": kv(false, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test431_UnknownQuiet(t *testing.T) {
	f := runRule(redshiftServerlessPublic{}, res("aws_redshiftserverless_workgroup", "main",
		map[string]ir.Value{"publicly_accessible": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test432_AbsentFires(t *testing.T) {
	f := runRule(redshiftServerlessNoKMS{}, res("aws_redshiftserverless_namespace", "main",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test432_SetQuiet(t *testing.T) {
	f := runRule(redshiftServerlessNoKMS{}, res("aws_redshiftserverless_namespace", "main",
		map[string]ir.Value{"kms_key_id": ks("arn:aws:kms:us-east-1:1234:key/abc", 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test432_UnknownQuiet(t *testing.T) {
	f := runRule(redshiftServerlessNoKMS{}, res("aws_redshiftserverless_namespace", "main",
		map[string]ir.Value{"kms_key_id": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test433_AbsentPolicyFires(t *testing.T) {
	// Absent policy = AWS default full-access endpoint policy.
	f := runRule(vpcEndpointPublicPolicy{}, res("aws_vpc_endpoint", "s3",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test433_PublicPolicyFires(t *testing.T) {
	f := runRule(vpcEndpointPublicPolicy{}, res("aws_vpc_endpoint", "s3",
		map[string]ir.Value{"policy": ks(publicPolicyDoc, 3)}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test433_RestrictedQuiet(t *testing.T) {
	f := runRule(vpcEndpointPublicPolicy{}, res("aws_vpc_endpoint", "s3",
		map[string]ir.Value{"policy": ks(restrictedPolicyDoc, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test433_UnknownQuiet(t *testing.T) {
	f := runRule(vpcEndpointPublicPolicy{}, res("aws_vpc_endpoint", "s3",
		map[string]ir.Value{"policy": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test434_AbsentFires(t *testing.T) {
	f := runRule(glueJobNoSecConfig{}, res("aws_glue_job", "etl",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test434_SetQuiet(t *testing.T) {
	f := runRule(glueJobNoSecConfig{}, res("aws_glue_job", "etl",
		map[string]ir.Value{"security_configuration": ks("sec-cfg", 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test434_UnknownQuiet(t *testing.T) {
	f := runRule(glueJobNoSecConfig{}, res("aws_glue_job", "etl",
		map[string]ir.Value{"security_configuration": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test435_AbsentFires(t *testing.T) {
	f := runRule(timestreamNoKMS{}, res("aws_timestreamwrite_database", "db",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test435_SetQuiet(t *testing.T) {
	f := runRule(timestreamNoKMS{}, res("aws_timestreamwrite_database", "db",
		map[string]ir.Value{"kms_key_id": ks("key-1", 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test435_UnknownQuiet(t *testing.T) {
	f := runRule(timestreamNoKMS{}, res("aws_timestreamwrite_database", "db",
		map[string]ir.Value{"kms_key_id": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test436_AbsentFires(t *testing.T) {
	f := runRule(rdsProxyNoTLS{}, res("aws_db_proxy", "app",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test436_FalseFires(t *testing.T) {
	f := runRule(rdsProxyNoTLS{}, res("aws_db_proxy", "app",
		map[string]ir.Value{"require_tls": kv(false, 3)}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test436_TrueQuiet(t *testing.T) {
	f := runRule(rdsProxyNoTLS{}, res("aws_db_proxy", "app",
		map[string]ir.Value{"require_tls": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test436_UnknownQuiet(t *testing.T) {
	f := runRule(rdsProxyNoTLS{}, res("aws_db_proxy", "app",
		map[string]ir.Value{"require_tls": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test437_TrueFires(t *testing.T) {
	f := runRule(appstreamDefaultInternet{}, res("aws_appstream_fleet", "office",
		map[string]ir.Value{"enable_default_internet_access": kv(true, 3)}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test437_FalseQuiet(t *testing.T) {
	f := runRule(appstreamDefaultInternet{}, res("aws_appstream_fleet", "office",
		map[string]ir.Value{"enable_default_internet_access": kv(false, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test437_UnknownQuiet(t *testing.T) {
	f := runRule(appstreamDefaultInternet{}, res("aws_appstream_fleet", "office",
		map[string]ir.Value{"enable_default_internet_access": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test438_AbsentFires(t *testing.T) {
	f := runRule(netFirewallNoDelProtect{}, res("aws_networkfirewall_firewall", "fw",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test438_TrueQuiet(t *testing.T) {
	f := runRule(netFirewallNoDelProtect{}, res("aws_networkfirewall_firewall", "fw",
		map[string]ir.Value{"delete_protection": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test438_UnknownQuiet(t *testing.T) {
	f := runRule(netFirewallNoDelProtect{}, res("aws_networkfirewall_firewall", "fw",
		map[string]ir.Value{"delete_protection": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test439_AbsentFires(t *testing.T) {
	f := runRule(memorydbNoSnapshots{}, res("aws_memorydb_cluster", "cache",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test439_ZeroFires(t *testing.T) {
	f := runRule(memorydbNoSnapshots{}, res("aws_memorydb_cluster", "cache",
		map[string]ir.Value{"snapshot_retention_limit": kn(0, 3)}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test439_RetentionQuiet(t *testing.T) {
	f := runRule(memorydbNoSnapshots{}, res("aws_memorydb_cluster", "cache",
		map[string]ir.Value{"snapshot_retention_limit": kn(7, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test439_UnknownQuiet(t *testing.T) {
	f := runRule(memorydbNoSnapshots{}, res("aws_memorydb_cluster", "cache",
		map[string]ir.Value{"snapshot_retention_limit": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test440_AbsentFires(t *testing.T) {
	f := runRule(neptuneNoDelProtect{}, res("aws_neptune_cluster", "graph",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test440_TrueQuiet(t *testing.T) {
	f := runRule(neptuneNoDelProtect{}, res("aws_neptune_cluster", "graph",
		map[string]ir.Value{"deletion_protection": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test440_UnknownQuiet(t *testing.T) {
	f := runRule(neptuneNoDelProtect{}, res("aws_neptune_cluster", "graph",
		map[string]ir.Value{"deletion_protection": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test441_PublicPolicyFires(t *testing.T) {
	f := runRule(s3AccessPointPublicPolicy{}, res("aws_s3control_access_point_policy", "ap",
		map[string]ir.Value{"policy": ks(publicPolicyDoc, 3)}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test441_RestrictedQuiet(t *testing.T) {
	f := runRule(s3AccessPointPublicPolicy{}, res("aws_s3control_access_point_policy", "ap",
		map[string]ir.Value{"policy": ks(restrictedPolicyDoc, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test441_UnknownQuiet(t *testing.T) {
	f := runRule(s3AccessPointPublicPolicy{}, res("aws_s3control_access_point_policy", "ap",
		map[string]ir.Value{"policy": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test442_AbsentFires(t *testing.T) {
	f := runRule(vpcEndpointSvcNoAccept{}, res("aws_vpc_endpoint_service", "svc",
		map[string]ir.Value{}))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
}

func Test442_TrueQuiet(t *testing.T) {
	f := runRule(vpcEndpointSvcNoAccept{}, res("aws_vpc_endpoint_service", "svc",
		map[string]ir.Value{"acceptance_required": kv(true, 3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func Test442_UnknownQuiet(t *testing.T) {
	f := runRule(vpcEndpointSvcNoAccept{}, res("aws_vpc_endpoint_service", "svc",
		map[string]ir.Value{"acceptance_required": ku(3)}))
	if len(f) != 0 {
		t.Fatalf("want 0 findings, got %d", len(f))
	}
}

func TestFinalRules_IDOrder(t *testing.T) {
	rules := FinalRules()
	if len(rules) != 12 {
		t.Fatalf("want 12 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := fmt.Sprintf("AEGIS-AWS-%d", 431+i)
		if r.ID() != want {
			t.Fatalf("rule %d: want ID %s, got %s", i, want, r.ID())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %s has empty metadata", r.ID())
		}
	}
}
