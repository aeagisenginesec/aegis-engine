package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-856: EC2 instance on an end-of-life OS image
//
// Positive: recognizable EOL OS markers (name fragment, filter glob,
// name_regex) fire. Negative: supported images, opaque AMI IDs,
// unresolved/interpolated values, and near-miss tokens stay quiet.
// ---------------------------------------------------------------------------

func eolRes(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return dsRes(typ, name, attrs)
}

func Test856_Debian10AMIFires(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("debian-10-amd64-20230101"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].RuleID != "AEGIS-AWS-856" {
		t.Fatalf("wrong rule ID: %s", f[0].RuleID)
	}
	if f[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected High severity, got %s", f[0].Severity)
	}
}

func Test856_Ubuntu1804ImageIDFires(t *testing.T) {
	r := eolRes("aws_launch_template", "lt", map[string]ir.Value{
		"image_id": dsStrVal("ubuntu-18.04-amd64-server-20230101"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test856_CentOS7Fires(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("centos-7-v20230101"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test856_AmazonLinux1Fires(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("amzn-ami-2018.03.0.20230101-x86_64-gp2"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test856_Windows2012R2Fires(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("windows-server-2012-r2-english-20230101"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test856_RHEL7Fires(t *testing.T) {
	r := eolRes("aws_spot_instance_request", "worker", map[string]ir.Value{
		"ami": dsStrVal("rhel-7.9-x86_64-20230101"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test856_BusterCodenameFires(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("debian-buster-amd64-20230101"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test856_AMIDataFilterGlobFires(t *testing.T) {
	filter := dsMapVal(map[string]ir.Value{
		"name":   dsStrVal("name"),
		"values": dsListVal([]ir.Value{dsStrVal("debian-10-amd64-*")}),
	})
	r := eolRes("terraform_data", "aws_ami.debian10", map[string]ir.Value{
		"filter": dsListVal([]ir.Value{filter}),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test856_AMIDataNameRegexFires(t *testing.T) {
	r := eolRes("terraform_data", "aws_ami.ubuntu", map[string]ir.Value{
		"name_regex": dsStrVal("ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func Test856_LaunchConfigurationFires(t *testing.T) {
	r := eolRes("aws_launch_configuration", "lc", map[string]ir.Value{
		"image_id": dsStrVal("ubuntu-1604-xenial-v20230101"),
	})
	f := (ec2EOLImage{}).Check(r)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

// --- negatives: supported images stay quiet ---

func Test856_Debian12Quiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("debian-12-bookworm-v20230101"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet, got %d findings: %v", len(got), got)
	}
}

func Test856_Ubuntu2204Quiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("ubuntu-22.04-amd64-server-20230101"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet, got %d findings: %v", len(got), got)
	}
}

func Test856_Ubuntu2404Quiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("ubuntu-24.04-amd64-server-20230101"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet, got %d findings: %v", len(got), got)
	}
}

func Test856_AL2023Quiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("al2023-ami-2023.1.20230101-x86_64"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet, got %d findings: %v", len(got), got)
	}
}

func Test856_RHEL9Quiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("rhel-9.2-x86_64-20230101"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet, got %d findings: %v", len(got), got)
	}
}

// --- negatives: unknown / opaque values stay quiet ---

func Test856_OpaqueAMIIDQuiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("ami-0abc123def45678901"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet on opaque AMI ID, got %d findings: %v", len(got), got)
	}
}

func Test856_UnknownValueQuiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": ir.Value{Known: false},
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet on unknown value, got %d findings: %v", len(got), got)
	}
}

func Test856_InterpolatedValueQuiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("${var.ami_id}"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet on interpolated value, got %d findings: %v", len(got), got)
	}
}

// --- negatives: anchoring — near-miss tokens must not match ---

func Test856_Debian101NoMatch(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"ami": dsStrVal("debian-101-custom-20230101"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet on debian-101, got %d findings: %v", len(got), got)
	}
}

func Test856_AMIDataSupportedFilterQuiet(t *testing.T) {
	filter := dsMapVal(map[string]ir.Value{
		"name":   dsStrVal("name"),
		"values": dsListVal([]ir.Value{dsStrVal("ubuntu-22.04-amd64-*")}),
	})
	r := eolRes("terraform_data", "aws_ami.ubuntu", map[string]ir.Value{
		"filter": dsListVal([]ir.Value{filter}),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet on supported filter, got %d findings: %v", len(got), got)
	}
}

func Test856_DataNonAMISourceQuiet(t *testing.T) {
	r := eolRes("terraform_data", "aws_instance.web", map[string]ir.Value{
		"ami": dsStrVal("debian-10-amd64-20230101"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet on non-aws_ami data source, got %d findings: %v", len(got), got)
	}
}

func Test856_NoAMIAttributeQuiet(t *testing.T) {
	r := eolRes("aws_instance", "web", map[string]ir.Value{
		"instance_type": dsStrVal("t3.micro"),
	})
	if got := (ec2EOLImage{}).Check(r); len(got) != 0 {
		t.Fatalf("expected quiet with no ami attribute, got %d findings: %v", len(got), got)
	}
}
