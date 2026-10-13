package aws

import (
	"testing"

	"aegis/internal/ir"
)

// num and itoa are defined in sibling test files (services_deep_test.go,
// attack_paths_multihop_test.go) and shared across the package.

func TestEC2IMDSTagsExposed(t *testing.T) {
	fire := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("instance_metadata_tags", ks("enabled", 3))),
	})
	quiet := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("instance_metadata_tags", ks("disabled", 3))),
	})
	unk := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("instance_metadata_tags", ku(3))),
	})
	if got := runRule(ec2IMDSTagsExposed{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ec2IMDSTagsExposed{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
	if got := runRule(ec2IMDSTagsExposed{}, unk); len(got) != 0 {
		t.Fatalf("unknown must not fire, got %d", len(got))
	}
}

func TestEC2IMDSHopLimitTooHigh(t *testing.T) {
	fire := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("http_put_response_hop_limit", num(2, 3))),
	})
	quiet := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("http_put_response_hop_limit", num(1, 3))),
	})
	unk := res("aws_instance", "web", map[string]ir.Value{
		"metadata_options": blks(2, blk("http_put_response_hop_limit", ku(3))),
	})
	if got := runRule(ec2IMDSHopLimitTooHigh{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ec2IMDSHopLimitTooHigh{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
	if got := runRule(ec2IMDSHopLimitTooHigh{}, unk); len(got) != 0 {
		t.Fatalf("unknown must not fire, got %d", len(got))
	}
}

func TestLaunchTemplateStaleDefault(t *testing.T) {
	absent := res("aws_launch_template", "lt", map[string]ir.Value{})
	quiet := res("aws_launch_template", "lt", map[string]ir.Value{
		"update_default_version": kv(true, 2),
	})
	explicitFalse := res("aws_launch_template", "lt", map[string]ir.Value{
		"update_default_version": kv(false, 2),
	})
	unk := res("aws_launch_template", "lt", map[string]ir.Value{
		"update_default_version": ku(2),
	})
	for _, r := range []ir.Resource{absent, explicitFalse} {
		if got := runRule(launchTemplateStaleDefault{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(launchTemplateStaleDefault{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
	if got := runRule(launchTemplateStaleDefault{}, unk); len(got) != 0 {
		t.Fatalf("unknown must not fire, got %d", len(got))
	}
}

func TestEC2NoTerminationProtection(t *testing.T) {
	absent := res("aws_instance", "web", map[string]ir.Value{})
	quiet := res("aws_instance", "web", map[string]ir.Value{
		"disable_api_termination": kv(true, 2),
	})
	if got := runRule(ec2NoTerminationProtection{}, absent); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ec2NoTerminationProtection{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}


func TestEC2PasswordDataExposed(t *testing.T) {
	fire := res("aws_instance", "win", map[string]ir.Value{
		"get_password_data": kv(true, 2),
	})
	quiet := res("aws_instance", "win", map[string]ir.Value{
		"get_password_data": kv(false, 2),
	})
	if got := runRule(ec2PasswordDataExposed{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ec2PasswordDataExposed{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestEC2UserDataAWSCreds(t *testing.T) {
	fire := res("aws_instance", "web", map[string]ir.Value{
		"user_data": ks("#!/bin/bash\nexport AWS_SECRET_ACCESS_KEY=hunter2value", 2),
	})
	fireKey := res("aws_instance", "web", map[string]ir.Value{
		"user_data": ks("echo AKIAIOSFODNN7EXAMPLE", 2),
	})
	quiet := res("aws_instance", "web", map[string]ir.Value{
		"user_data": ks("#!/bin/bash\necho hello", 2),
	})
	unk := res("aws_instance", "web", map[string]ir.Value{
		"user_data": ku(2),
	})
	for _, r := range []ir.Resource{fire, fireKey} {
		got := runRule(ec2UserDataAWSCreds{}, r)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
		if got[0].Evidence.Actual != "[REDACTED] (AWS credential assignment in user_data)" {
			t.Fatalf("secret leaked in evidence: %q", got[0].Evidence.Actual)
		}
	}
	for _, r := range []ir.Resource{quiet, unk} {
		if got := runRule(ec2UserDataAWSCreds{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestLTUserDataHardcodedPassword(t *testing.T) {
	fire := res("aws_launch_template", "lt", map[string]ir.Value{
		"user_data": ks("#!/bin/bash\necho 'dbuser:password=s3cr3t!' | chpasswd", 2),
	})
	quiet := res("aws_launch_template", "lt", map[string]ir.Value{
		"user_data": ks("#!/bin/bash\nyum install -y nginx", 2),
	})
	if got := runRule(ltUserDataHardcodedPassword{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ltUserDataHardcodedPassword{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestENIPublicIPAssociated(t *testing.T) {
	fire := res("aws_network_interface", "eni", map[string]ir.Value{
		"associate_public_ip_address": kv(true, 2),
	})
	quiet := res("aws_network_interface", "eni", map[string]ir.Value{
		"associate_public_ip_address": kv(false, 2),
	})
	wrongType := res("aws_instance", "web", map[string]ir.Value{
		"associate_public_ip_address": kv(true, 2), // AEGIS-AWS-444's scope
	})
	if got := runRule(eniPublicIPAssociated{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	for _, r := range []ir.Resource{quiet, wrongType} {
		if got := runRule(eniPublicIPAssociated{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestEC2SourceDestCheckDisabled(t *testing.T) {
	fire := res("aws_instance", "web", map[string]ir.Value{
		"source_dest_check": kv(false, 2),
	})
	quiet := res("aws_instance", "web", map[string]ir.Value{
		"source_dest_check": kv(true, 2),
	})
	if got := runRule(ec2SourceDestCheckDisabled{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ec2SourceDestCheckDisabled{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestASGHealthCheckEC2Only(t *testing.T) {
	fire := res("aws_autoscaling_group", "asg", map[string]ir.Value{
		"health_check_type": ks("EC2", 2),
	})
	quiet := res("aws_autoscaling_group", "asg", map[string]ir.Value{
		"health_check_type": ks("ELB", 2),
	})
	if got := runRule(asgHealthCheckEC2Only{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(asgHealthCheckEC2Only{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestLTEBSOptimizedAbsent(t *testing.T) {
	absent := res("aws_launch_template", "lt", map[string]ir.Value{})
	quiet := res("aws_launch_template", "lt", map[string]ir.Value{
		"ebs_optimized": kv(true, 2),
	})
	if got := runRule(ltEBSOptimizedAbsent{}, absent); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ltEBSOptimizedAbsent{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}


func TestEC2UnlimitedCPUCredits(t *testing.T) {
	fire := res("aws_instance", "web", map[string]ir.Value{
		"credit_specification": blks(2, blk("cpu_credits", ks("unlimited", 3))),
	})
	quiet := res("aws_instance", "web", map[string]ir.Value{
		"credit_specification": blks(2, blk("cpu_credits", ks("standard", 3))),
	})
	if got := runRule(ec2UnlimitedCPUCredits{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ec2UnlimitedCPUCredits{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestAMICopyUnencrypted(t *testing.T) {
	absent := res("aws_ami_copy", "copy", map[string]ir.Value{})
	explicit := res("aws_ami_copy", "copy", map[string]ir.Value{
		"encrypted": kv(false, 2),
	})
	quiet := res("aws_ami_copy", "copy", map[string]ir.Value{
		"encrypted": kv(true, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(amiCopyUnencrypted{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(amiCopyUnencrypted{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestEBSSnapshotCopyUnencrypted(t *testing.T) {
	absent := res("aws_ebs_snapshot_copy", "copy", map[string]ir.Value{})
	quiet := res("aws_ebs_snapshot_copy", "copy", map[string]ir.Value{
		"encrypted": kv(true, 2),
	})
	if got := runRule(ebsSnapshotCopyUnencrypted{}, absent); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ebsSnapshotCopyUnencrypted{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestEC2RootVolumeUnencrypted(t *testing.T) {
	// Absent root_block_device: encryption follows the AMI snapshot +
	// account EBS-encryption-by-default, NOT a provider default of
	// unencrypted. Absent block and absent encrypted both stay quiet;
	// only explicit encrypted = false fires.
	absentBlock := res("aws_instance", "web", map[string]ir.Value{})
	absentEncrypted := res("aws_instance", "web", map[string]ir.Value{
		"root_block_device": blks(2, blk()),
	})
	explicit := res("aws_instance", "web", map[string]ir.Value{
		"root_block_device": blks(2, blk("encrypted", kv(false, 3))),
	})
	quiet := res("aws_instance", "web", map[string]ir.Value{
		"root_block_device": blks(2, blk("encrypted", kv(true, 3))),
	})
	if got := runRule(ec2RootVolumeUnencrypted{}, explicit); len(got) != 1 {
		t.Fatalf("expected 1 finding on explicit encrypted=false, got %d", len(got))
	}
	for _, r := range []ir.Resource{absentBlock, absentEncrypted, quiet} {
		if got := runRule(ec2RootVolumeUnencrypted{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestLTEBSDeleteOnTermination(t *testing.T) {
	fire := res("aws_launch_template", "lt", map[string]ir.Value{
		"block_device_mappings": blks(2,
			blk("ebs", blks(3, blk("delete_on_termination", kv(false, 4), "volume_size", num(20, 4)))),
		),
	})
	quiet := res("aws_launch_template", "lt", map[string]ir.Value{
		"block_device_mappings": blks(2,
			blk("ebs", blks(3, blk("delete_on_termination", kv(true, 4)))),
		),
	})
	if got := runRule(ltEBSDeleteOnTermination{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(ltEBSDeleteOnTermination{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestASGNoScalingRange(t *testing.T) {
	fire := res("aws_autoscaling_group", "asg", map[string]ir.Value{
		"min_size": num(2, 2),
		"max_size": num(2, 3),
	})
	quiet := res("aws_autoscaling_group", "asg", map[string]ir.Value{
		"min_size": num(1, 2),
		"max_size": num(3, 3),
	})
	unk := res("aws_autoscaling_group", "asg", map[string]ir.Value{
		"min_size": num(2, 2),
		"max_size": ku(3),
	})
	if got := runRule(asgNoScalingRange{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	for _, r := range []ir.Resource{quiet, unk} {
		if got := runRule(asgNoScalingRange{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestEC2NoNitroEnclaves(t *testing.T) {
	absent := res("aws_instance", "web", map[string]ir.Value{})
	quiet := res("aws_instance", "web", map[string]ir.Value{
		"enclave_options": blks(2, blk("enabled", kv(true, 3))),
	})
	explicitFalse := res("aws_instance", "web", map[string]ir.Value{
		"enclave_options": blks(2, blk("enabled", kv(false, 3))),
	})
	for _, r := range []ir.Resource{absent, explicitFalse} {
		if got := runRule(ec2NoNitroEnclaves{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(ec2NoNitroEnclaves{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

// TestComputeDeepRuleIDs asserts the 680-699 ID range is covered
// (minus 684 removed as factually wrong, 692 removed as inverted).
func TestComputeDeepRuleIDs(t *testing.T) {
	rules := ComputeDeepRules()
	wantIDs := []string{
		"AEGIS-AWS-680", "AEGIS-AWS-681", "AEGIS-AWS-682", "AEGIS-AWS-683",
		"AEGIS-AWS-685", "AEGIS-AWS-686", "AEGIS-AWS-687", "AEGIS-AWS-688",
		"AEGIS-AWS-689", "AEGIS-AWS-690", "AEGIS-AWS-691",
		"AEGIS-AWS-693", "AEGIS-AWS-694", "AEGIS-AWS-695", "AEGIS-AWS-696",
		"AEGIS-AWS-697", "AEGIS-AWS-698", "AEGIS-AWS-699",
	}
	if len(rules) != len(wantIDs) {
		t.Fatalf("expected %d rules, got %d", len(wantIDs), len(rules))
	}
	for i, r := range rules {
		if r.ID() != wantIDs[i] {
			t.Fatalf("rule %d has ID %q, want %q", i, r.ID(), wantIDs[i])
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %s has empty metadata", r.ID())
		}
	}
}
