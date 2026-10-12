package aws

import (
	"testing"

	"aegis/internal/ir"
)

// kn: known number value (adapter stores HCL numbers as float64).
func kn(f float64, line int) ir.Value { return ir.Value{Raw: f, Known: true, Span: spanAt(line)} }

// runCross executes a CrossResourceRule against the full set.
func runCross(rule ir.CrossResourceRule, resources ...ir.Resource) []ir.Finding {
	return rule.CheckAll(resources)
}

// --- AEGIS-AWS-201 ----------------------------------------------------

func Test201_AbsentInternalFires(t *testing.T) {
	fs := runRule(lbInternetFacing{}, res("aws_lb", "web", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Evidence.Actual != "false (default)" {
		t.Errorf("actual = %q", fs[0].Evidence.Actual)
	}
}

func Test201_FalseFires(t *testing.T) {
	fs := runRule(lbInternetFacing{},
		res("aws_alb", "web", map[string]ir.Value{"internal": kv(false, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test201_InternalTrueQuiet(t *testing.T) {
	fs := runRule(lbInternetFacing{},
		res("aws_lb", "int", map[string]ir.Value{"internal": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test201_UnknownQuiet(t *testing.T) {
	fs := runRule(lbInternetFacing{},
		res("aws_lb", "x", map[string]ir.Value{"internal": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-202 ----------------------------------------------------

func Test202_HTTPFires(t *testing.T) {
	fs := runRule(lbListenerPlainHTTP{},
		res("aws_lb_listener", "web", map[string]ir.Value{"protocol": ks("HTTP", 4)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityCritical {
		t.Errorf("severity = %v, want critical", fs[0].Severity)
	}
}

func Test202_HTTPSQuiet(t *testing.T) {
	fs := runRule(lbListenerPlainHTTP{},
		res("aws_alb_listener", "web", map[string]ir.Value{"protocol": ks("HTTPS", 4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test202_UnknownQuiet(t *testing.T) {
	fs := runRule(lbListenerPlainHTTP{},
		res("aws_lb_listener", "x", map[string]ir.Value{"protocol": ku(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test202_CaseInsensitive(t *testing.T) {
	fs := runRule(lbListenerPlainHTTP{},
		res("aws_lb_listener", "x", map[string]ir.Value{"protocol": ks("http", 4)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

// --- AEGIS-AWS-203 ----------------------------------------------------

func Test203_AbsentFires(t *testing.T) {
	fs := runRule(lbNoHeaderDrop{}, res("aws_lb", "web", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test203_TrueQuiet(t *testing.T) {
	fs := runRule(lbNoHeaderDrop{},
		res("aws_alb", "web", map[string]ir.Value{"drop_invalid_header_fields": kv(true, 5)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test203_UnknownQuiet(t *testing.T) {
	fs := runRule(lbNoHeaderDrop{},
		res("aws_lb", "x", map[string]ir.Value{"drop_invalid_header_fields": ku(5)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-204 ----------------------------------------------------

func Test204_AbsentBlockFires(t *testing.T) {
	fs := runRule(ec2NoIMDSv2{}, res("aws_instance", "web", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test204_OptionalTokensFires(t *testing.T) {
	fs := runRule(ec2NoIMDSv2{}, res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(6, blk("http_tokens", ks("optional", 7))),
	}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test204_RequiredQuiet(t *testing.T) {
	fs := runRule(ec2NoIMDSv2{}, res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(6, blk("http_tokens", ks("required", 7))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test204_UnknownTokensQuiet(t *testing.T) {
	fs := runRule(ec2NoIMDSv2{}, res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(6, blk("http_tokens", ku(7))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-205 ----------------------------------------------------

func Test205_TrueFires(t *testing.T) {
	fs := runRule(subnetPublicIP{},
		res("aws_subnet", "pub", map[string]ir.Value{"map_public_ip_on_launch": kv(true, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test205_FalseQuiet(t *testing.T) {
	fs := runRule(subnetPublicIP{},
		res("aws_subnet", "priv", map[string]ir.Value{"map_public_ip_on_launch": kv(false, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test205_UnknownQuiet(t *testing.T) {
	fs := runRule(subnetPublicIP{},
		res("aws_subnet", "x", map[string]ir.Value{"map_public_ip_on_launch": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-206 ----------------------------------------------------

func pabFixture(name, bucketRefPath string, allTrue bool, line int) ir.Resource {
	attrs := map[string]ir.Value{"bucket": bucketRef(line, bucketRefPath)}
	for _, n := range []string{
		"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets",
	} {
		attrs[n] = kv(allTrue, line+1)
	}
	return res("aws_s3_bucket_public_access_block", name, attrs)
}

func Test206_NoBlockFires(t *testing.T) {
	fs := runCross(s3NoPublicAccessBlock{}, bucketFixture("assets"))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test206_FullBlockQuiet(t *testing.T) {
	fs := runCross(s3NoPublicAccessBlock{},
		bucketFixture("assets"),
		pabFixture("assets", "aws_s3_bucket.assets.id", true, 10),
	)
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test206_PartialBlockFires(t *testing.T) {
	b := bucketFixture("assets")
	pab := pabFixture("assets", "aws_s3_bucket.assets.id", true, 10)
	pab.Attributes["restrict_public_buckets"] = kv(false, 11)
	fs := runCross(s3NoPublicAccessBlock{}, b, pab)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test206_BlockForOtherBucketFires(t *testing.T) {
	fs := runCross(s3NoPublicAccessBlock{},
		bucketFixture("assets"),
		bucketFixture("logs"),
		pabFixture("logs", "aws_s3_bucket.logs.id", true, 10),
	)
	if len(fs) != 1 || fs[0].Resource != "aws_s3_bucket.assets" {
		t.Fatalf("got %+v, want one finding for aws_s3_bucket.assets", fs)
	}
}

func Test206_KnownNameLinkQuiet(t *testing.T) {
	fs := runCross(s3NoPublicAccessBlock{},
		res("aws_s3_bucket", "assets", map[string]ir.Value{"bucket": ks("my-bucket", 3)}),
		res("aws_s3_bucket_public_access_block", "assets", map[string]ir.Value{
			"bucket":                  ks("my-bucket", 10),
			"block_public_acls":       kv(true, 11),
			"block_public_policy":     kv(true, 12),
			"ignore_public_acls":      kv(true, 13),
			"restrict_public_buckets": kv(true, 14),
		}),
	)
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-207 ----------------------------------------------------

func Test207_AbsentFires(t *testing.T) {
	fs := runRule(rdsNoBackup{}, res("aws_db_instance", "db", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test207_ZeroFires(t *testing.T) {
	fs := runRule(rdsNoBackup{},
		res("aws_db_instance", "db", map[string]ir.Value{"backup_retention_period": kn(0, 8)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test207_PositiveQuiet(t *testing.T) {
	fs := runRule(rdsNoBackup{},
		res("aws_db_instance", "db", map[string]ir.Value{"backup_retention_period": kn(7, 8)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test207_UnknownQuiet(t *testing.T) {
	fs := runRule(rdsNoBackup{},
		res("aws_db_instance", "db", map[string]ir.Value{"backup_retention_period": ku(8)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-208 ----------------------------------------------------

func Test208_AbsentFires(t *testing.T) {
	fs := runRule(elasticacheNoSnapshots{},
		res("aws_elasticache_replication_group", "cache", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test208_ZeroFires(t *testing.T) {
	fs := runRule(elasticacheNoSnapshots{},
		res("aws_elasticache_replication_group", "cache",
			map[string]ir.Value{"snapshot_retention_limit": kn(0, 8)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test208_PositiveQuiet(t *testing.T) {
	fs := runRule(elasticacheNoSnapshots{},
		res("aws_elasticache_replication_group", "cache",
			map[string]ir.Value{"snapshot_retention_limit": kn(5, 8)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test208_UnknownQuiet(t *testing.T) {
	fs := runRule(elasticacheNoSnapshots{},
		res("aws_elasticache_replication_group", "cache",
			map[string]ir.Value{"snapshot_retention_limit": ku(8)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-209 ----------------------------------------------------

func vpcFixture(name string) ir.Resource {
	return res("aws_vpc", name, map[string]ir.Value{})
}

func flowLogFixture(name, vpcRefPath string, line int) ir.Resource {
	return res("aws_flow_log", name, map[string]ir.Value{
		"vpc_id": bucketRef(line, vpcRefPath),
	})
}

func subnetFixture(name, vpcRefPath string, line int) ir.Resource {
	return res("aws_subnet", name, map[string]ir.Value{
		"vpc_id": bucketRef(line, vpcRefPath),
	})
}

func Test209_NoFlowLogFires(t *testing.T) {
	fs := runCross(vpcNoFlowLogs{},
		vpcFixture("main"),
		subnetFixture("a", "aws_vpc.main.id", 10),
	)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

// A VPC with no subnets carries no traffic: flow logs would capture
// nothing, so the rule stays silent. Regression: held-out clean projects
// ship a placeholder VPC in an uninstantiated module.
func Test209_NoSubnetsSilent(t *testing.T) {
	fs := runCross(vpcNoFlowLogs{}, vpcFixture("main"))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0 for subnet-less VPC", len(fs))
	}
}

// A subnet whose vpc_id is unresolvable might belong to any VPC: fail-safe,
// the VPC is still flagged.
func Test209_UnresolvableSubnetVPCIDFires(t *testing.T) {
	fs := runCross(vpcNoFlowLogs{},
		vpcFixture("main"),
		res("aws_subnet", "a", map[string]ir.Value{"vpc_id": ku(10)}),
	)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test209_LinkedFlowLogQuiet(t *testing.T) {
	fs := runCross(vpcNoFlowLogs{},
		vpcFixture("main"),
		flowLogFixture("vpc", "aws_vpc.main.id", 10),
	)
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test209_FlowLogForOtherVPCFires(t *testing.T) {
	fs := runCross(vpcNoFlowLogs{},
		vpcFixture("main"),
		vpcFixture("other"),
		subnetFixture("a", "aws_vpc.main.id", 10),
		flowLogFixture("other", "aws_vpc.other.id", 10),
	)
	if len(fs) != 1 || fs[0].Resource != "aws_vpc.main" {
		t.Fatalf("got %+v, want one finding for aws_vpc.main", fs)
	}
}

func Test209_KnownNameLinkQuiet(t *testing.T) {
	fs := runCross(vpcNoFlowLogs{},
		vpcFixture("main"),
		res("aws_flow_log", "vpc", map[string]ir.Value{"vpc_id": ks("main", 10)}),
	)
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- determinism -------------------------------------------------------

func TestCoverage2_Deterministic(t *testing.T) {
	resources := []ir.Resource{
		vpcFixture("main"),
		bucketFixture("assets"),
		pabFixture("assets", "aws_s3_bucket.assets.id", false, 10),
		res("aws_lb", "web", map[string]ir.Value{}),
		res("aws_instance", "web", map[string]ir.Value{}),
	}
	once := s3NoPublicAccessBlock{}.CheckAll(resources)
	twice := s3NoPublicAccessBlock{}.CheckAll(append([]ir.Resource(nil), resources...))
	if len(once) != len(twice) {
		t.Fatalf("nondeterministic: %d vs %d", len(once), len(twice))
	}
	for i := range once {
		if once[i].RuleID != twice[i].RuleID || once[i].Resource != twice[i].Resource {
			t.Fatalf("nondeterministic finding %d", i)
		}
	}
}

func Test204_LaunchTemplateAbsentBlockFires(t *testing.T) {
	if !(ec2NoIMDSv2{}).AppliesTo("aws_launch_template") {
		t.Fatal("204 must apply to aws_launch_template")
	}
	fs := runRule(ec2NoIMDSv2{}, res("aws_launch_template", "web", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test204_LaunchTemplateRequiredQuiet(t *testing.T) {
	fs := runRule(ec2NoIMDSv2{}, res("aws_launch_template", "web", map[string]ir.Value{
		"metadata_options": blks(6, blk("http_tokens", ks("required", 7))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}
