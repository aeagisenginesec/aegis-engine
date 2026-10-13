package aws

import (
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

func Test851_NoIntegrationFires(t *testing.T) {
	// Neither attribute: no integration.
	r := res("aws_cloudtrail", "ct", map[string]ir.Value{})
	if f := runRule(cloudtrailNoCloudWatch{}, r); len(f) != 1 || f[0].RuleID != "AEGIS-AWS-851" {
		t.Errorf("expected 851 to fire on trail without CloudWatch, got %+v", f)
	}
}

func Test851_PartialIntegrationFires(t *testing.T) {
	// Only the group set: role missing, integration cannot function.
	r := res("aws_cloudtrail", "ct", map[string]ir.Value{
		"cloud_watch_logs_group_arn": ks("arn:aws:logs:us-east-1:123456789012:log-group:ct", 3),
	})
	if f := runRule(cloudtrailNoCloudWatch{}, r); len(f) != 1 {
		t.Errorf("expected 851 to fire on group-only trail, got %+v", f)
	}
	// Only the role set: group missing.
	r = res("aws_cloudtrail", "ct", map[string]ir.Value{
		"cloud_watch_logs_role_arn": ks("arn:aws:iam::123456789012:role/ct-cw", 3),
	})
	if f := runRule(cloudtrailNoCloudWatch{}, r); len(f) != 1 {
		t.Errorf("expected 851 to fire on role-only trail, got %+v", f)
	}
}

func Test851_FullIntegrationQuiet(t *testing.T) {
	r := res("aws_cloudtrail", "ct", map[string]ir.Value{
		"cloud_watch_logs_group_arn": ks("arn:aws:logs:us-east-1:123456789012:log-group:ct", 3),
		"cloud_watch_logs_role_arn":  ks("arn:aws:iam::123456789012:role/ct-cw", 3),
	})
	if f := runRule(cloudtrailNoCloudWatch{}, r); len(f) != 0 {
		t.Errorf("expected quiet on fully integrated trail, got %+v", f)
	}
}

func Test851_UnknownQuiet(t *testing.T) {
	r := res("aws_cloudtrail", "ct", map[string]ir.Value{
		"cloud_watch_logs_group_arn": ku(3),
	})
	if f := runRule(cloudtrailNoCloudWatch{}, r); len(f) != 0 {
		t.Errorf("expected quiet on unknown group ARN, got %+v", f)
	}
}

func Test851_TerraformFixture(t *testing.T) {
	src := `
resource "aws_cloudtrail" "ct" {
  name = "ct"
  s3_bucket_name = "logs"
}
resource "aws_cloudtrail" "ct2" {
  name = "ct2"
  s3_bucket_name = "logs"
  cloud_watch_logs_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:ct2"
  cloud_watch_logs_role_arn = "arn:aws:iam::123456789012:role/ct-cw"
}
`
	rs, _, err := terraform.New().Parse("main.tf", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var fired []string
	for _, r := range rs {
		if r.Type != "aws_cloudtrail" {
			continue
		}
		if f := runRule(cloudtrailNoCloudWatch{}, r); len(f) == 1 {
			fired = append(fired, r.Name)
		}
	}
	if len(fired) != 1 || fired[0] != "ct" {
		t.Errorf("expected 851 on ct only, got %v", fired)
	}
}
