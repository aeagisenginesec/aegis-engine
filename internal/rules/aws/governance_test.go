package aws

import (
	"testing"

	"aegis/internal/ir"
)

func Test391_DisabledFires(t *testing.T) {
	r := res("aws_ebs_encryption_by_default", "x", map[string]ir.Value{"enabled": kv(false, 3)})
	fs := runRule(ebsDefaultEncryptionDisabled{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium, got %s", fs[0].Severity)
	}
}

func Test391_EnabledQuiet(t *testing.T) {
	r := res("aws_ebs_encryption_by_default", "x", map[string]ir.Value{"enabled": kv(true, 3)})
	if fs := runRule(ebsDefaultEncryptionDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test391_UnknownQuiet(t *testing.T) {
	r := res("aws_ebs_encryption_by_default", "x", map[string]ir.Value{"enabled": ku(3)})
	if fs := runRule(ebsDefaultEncryptionDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test392_AbsentFires(t *testing.T) {
	r := res("aws_backup_vault", "v", map[string]ir.Value{})
	fs := runRule(backupVaultNoKMS{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test392_WithKeyQuiet(t *testing.T) {
	r := res("aws_backup_vault", "v", map[string]ir.Value{"kms_key_arn": ks("arn:aws:kms:x", 3)})
	if fs := runRule(backupVaultNoKMS{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test392_UnknownQuiet(t *testing.T) {
	r := res("aws_backup_vault", "v", map[string]ir.Value{"kms_key_arn": ku(3)})
	if fs := runRule(backupVaultNoKMS{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test393_AllSupportedFalseFires(t *testing.T) {
	r := res("aws_config_configuration_recorder", "r", map[string]ir.Value{
		"recording_group": blks(4, blk("all_supported", kv(false, 5))),
	})
	fs := runRule(configRecorderDisabled{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test393_AllSupportedTrueQuiet(t *testing.T) {
	r := res("aws_config_configuration_recorder", "r", map[string]ir.Value{
		"recording_group": blks(4, blk("all_supported", kv(true, 5))),
	})
	if fs := runRule(configRecorderDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test393_NoBlockQuiet(t *testing.T) {
	r := res("aws_config_configuration_recorder", "r", map[string]ir.Value{})
	if fs := runRule(configRecorderDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0 (default records all)", len(fs))
	}
}

func Test393_UnknownQuiet(t *testing.T) {
	r := res("aws_config_configuration_recorder", "r", map[string]ir.Value{
		"recording_group": blks(4, blk("all_supported", ku(5))),
	})
	if fs := runRule(configRecorderDisabled{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test394_ExplicitFalseFires(t *testing.T) {
	r := res("aws_elastic_beanstalk_environment", "e", map[string]ir.Value{
		"setting": blks(4, blk(
			"namespace", ks("aws:elasticbeanstalk:managedactions", 5),
			"name", ks("ManagedActionsEnabled", 6),
			"value", ks("false", 7),
		)),
	})
	fs := runRule(beanstalkNoManagedUpdates{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test394_TrueQuiet(t *testing.T) {
	r := res("aws_elastic_beanstalk_environment", "e", map[string]ir.Value{
		"setting": blks(4, blk(
			"namespace", ks("aws:elasticbeanstalk:managedactions", 5),
			"name", ks("ManagedActionsEnabled", 6),
			"value", ks("true", 7),
		)),
	})
	if fs := runRule(beanstalkNoManagedUpdates{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test394_NoSettingQuiet(t *testing.T) {
	r := res("aws_elastic_beanstalk_environment", "e", map[string]ir.Value{
		"setting": blks(4, blk(
			"namespace", ks("aws:elasticbeanstalk:application", 5),
			"name", ks("Application Healthcheck URL", 6),
			"value", ks("/", 7),
		)),
	})
	if fs := runRule(beanstalkNoManagedUpdates{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test394_UnknownValueQuiet(t *testing.T) {
	r := res("aws_elastic_beanstalk_environment", "e", map[string]ir.Value{
		"setting": blks(4, blk(
			"namespace", ks("aws:elasticbeanstalk:managedactions", 5),
			"name", ks("ManagedActionsEnabled", 6),
			"value", ku(7),
		)),
	})
	if fs := runRule(beanstalkNoManagedUpdates{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test395_AbsentBlockFires(t *testing.T) {
	r := res("aws_apprunner_service", "s", map[string]ir.Value{})
	fs := runRule(appRunnerNoKMS{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test395_WithKeyQuiet(t *testing.T) {
	r := res("aws_apprunner_service", "s", map[string]ir.Value{
		"encryption_configuration": blks(4, blk("kms_key", ks("arn:aws:kms:x", 5))),
	})
	if fs := runRule(appRunnerNoKMS{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test395_EmptyKeyFires(t *testing.T) {
	r := res("aws_apprunner_service", "s", map[string]ir.Value{
		"encryption_configuration": blks(4, blk("kms_key", ks("", 5))),
	})
	fs := runRule(appRunnerNoKMS{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test395_UnknownBlockQuiet(t *testing.T) {
	r := res("aws_apprunner_service", "s", map[string]ir.Value{
		"encryption_configuration": ir.Value{Known: false, Span: spanAt(4)},
	})
	if fs := runRule(appRunnerNoKMS{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test396_PresenceFires(t *testing.T) {
	r := res("aws_default_vpc", "default", map[string]ir.Value{})
	fs := runRule(defaultVPCInUse{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Resource != "aws_default_vpc.default" {
		t.Fatalf("wrong resource: %s", fs[0].Resource)
	}
}

func Test396_WrongTypeQuiet(t *testing.T) {
	if (defaultVPCInUse{}).AppliesTo("aws_vpc") {
		t.Fatal("396 must not apply to aws_vpc")
	}
}

func Test397_IngressFires(t *testing.T) {
	r := res("aws_default_security_group", "d", map[string]ir.Value{
		"ingress": blks(4, blk("from_port", kv(true, 5))),
	})
	fs := runRule(defaultSGIngress{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test397_NoIngressQuiet(t *testing.T) {
	r := res("aws_default_security_group", "d", map[string]ir.Value{})
	if fs := runRule(defaultSGIngress{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test397_UnknownQuiet(t *testing.T) {
	r := res("aws_default_security_group", "d", map[string]ir.Value{
		"ingress": ir.Value{Known: false, Span: spanAt(4)},
	})
	if fs := runRule(defaultSGIngress{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test398_TrueFires(t *testing.T) {
	r := res("aws_vpc_peering_connection", "p", map[string]ir.Value{"auto_accept": kv(true, 3)})
	fs := runRule(vpcPeeringAutoAccept{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test398_FalseQuiet(t *testing.T) {
	r := res("aws_vpc_peering_connection", "p", map[string]ir.Value{"auto_accept": kv(false, 3)})
	if fs := runRule(vpcPeeringAutoAccept{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test398_UnknownQuiet(t *testing.T) {
	r := res("aws_vpc_peering_connection", "p", map[string]ir.Value{"auto_accept": ku(3)})
	if fs := runRule(vpcPeeringAutoAccept{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test399_TrueFires(t *testing.T) {
	r := res("aws_ram_resource_share", "s", map[string]ir.Value{"allow_external_principals": kv(true, 3)})
	fs := runRule(ramShareExternal{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high, got %s", fs[0].Severity)
	}
}

func Test399_FalseQuiet(t *testing.T) {
	r := res("aws_ram_resource_share", "s", map[string]ir.Value{"allow_external_principals": kv(false, 3)})
	if fs := runRule(ramShareExternal{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test399_UnknownQuiet(t *testing.T) {
	r := res("aws_ram_resource_share", "s", map[string]ir.Value{"allow_external_principals": ku(3)})
	if fs := runRule(ramShareExternal{}, r); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test400_PresenceFires(t *testing.T) {
	r := res("aws_default_subnet", "a", map[string]ir.Value{"availability_zone": ks("us-east-1a", 2)})
	fs := runRule(defaultSubnetInUse{}, r)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test400_WrongTypeQuiet(t *testing.T) {
	if (defaultSubnetInUse{}).AppliesTo("aws_subnet") {
		t.Fatal("400 must not apply to aws_subnet")
	}
}

func TestGovernanceRules_IDOrder(t *testing.T) {
	rules := GovernanceRules()
	want := []string{
		"AEGIS-AWS-391", "AEGIS-AWS-392", "AEGIS-AWS-393", "AEGIS-AWS-394", "AEGIS-AWS-395",
		"AEGIS-AWS-396", "AEGIS-AWS-397", "AEGIS-AWS-398", "AEGIS-AWS-399", "AEGIS-AWS-400",
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("rule %d: got %s, want %s", i, rules[i].ID(), w)
		}
		if rules[i].Title() == "" || rules[i].Description() == "" {
			t.Fatalf("rule %s has empty metadata", w)
		}
	}
}
