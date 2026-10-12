package cloudformation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/ir"
	"aegis/internal/rules"
)

// scanTemplate parses src as a CloudFormation template and runs the full
// AWS rule registry over the resulting resources.
func scanTemplate(t *testing.T, name, src string) []ir.Finding {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	ad := New()
	if !ad.Handles(path) {
		t.Fatalf("adapter does not handle %s", path)
	}
	resources, diags, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("diagnostic error: %s", d.Message)
		}
	}
	reg := rules.DefaultRegistry()
	return reg.Run(resources)
}

func ruleIDs(findings []ir.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range findings {
		m[f.RuleID] = true
	}
	return m
}

func TestHandlesDetection(t *testing.T) {
	ad := New()
	cfnYAML := "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n"
	cfnJSON := `{"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}`
	k8s := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n"
	tfPlan := `{"planned_values": {}}`

	cases := []struct {
		name     string
		filename string
		src      string
		want     bool
	}{
		{"yaml template", "template.yaml", cfnYAML, true},
		{"yml template", "template.yml", cfnYAML, true},
		{"json template", "template.json", cfnJSON, true},
		{"k8s manifest", "deploy.yaml", k8s, false},
		{"plan json", "tf.plan.json", tfPlan, false},
		{"tf file", "main.tf", cfnYAML, false},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), c.filename)
		os.WriteFile(path, []byte(c.src), 0o600)
		if got := ad.Handles(path); got != c.want {
			t.Errorf("%s: Handles=%v want %v", c.name, got, c.want)
		}
	}
}

func TestS3Vulnerable(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-data-bucket
`
	findings := scanTemplate(t, "template.yaml", src)
	ids := ruleIDs(findings)
	if !ids["AEGIS-AWS-001"] {
		t.Errorf("expected AEGIS-AWS-001 (unencrypted bucket), got %v", ids)
	}
}

func TestS3Secure(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      VersioningConfiguration:
        Status: Enabled
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
`
	findings := scanTemplate(t, "template.yaml", src)
	ids := ruleIDs(findings)
	if ids["AEGIS-AWS-001"] {
		t.Errorf("did not expect AEGIS-AWS-001 on encrypted bucket")
	}
}

func TestS3JSON(t *testing.T) {
	src := `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "DataBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {"BucketName": "x"}
    }
  }
}`
	findings := scanTemplate(t, "template.json", src)
	if !ruleIDs(findings)["AEGIS-AWS-001"] {
		t.Errorf("expected AEGIS-AWS-001 from JSON template")
	}
}

func TestIAMRoleWildcard(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: '*'
            Action: sts:AssumeRole
      Policies:
        - PolicyName: admin
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: '*'
                Resource: '*'
`
	findings := scanTemplate(t, "template.yaml", src)
	ids := ruleIDs(findings)
	// Wildcard action on * resource should trip IAM privilege rules.
	found := false
	for id := range ids {
		if strings.HasPrefix(id, "AEGIS-AWS-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected IAM findings for wildcard policy, got none")
	}
}

func TestIAMRoleSecure(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
`
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	resources, _, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	r := resources[0]
	if r.Type != "aws_iam_role" {
		t.Errorf("type = %s, want aws_iam_role", r.Type)
	}
	v, ok := r.Attributes["assume_role_policy"]
	if !ok || !v.Known {
		t.Fatalf("assume_role_policy missing or unknown")
	}
	s, _ := v.AsString()
	if !strings.Contains(s, "ec2.amazonaws.com") {
		t.Errorf("assume_role_policy JSON missing principal: %s", s)
	}
}

func TestEC2Vulnerable(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
`
	findings := scanTemplate(t, "template.yaml", src)
	if len(findings) == 0 {
		t.Errorf("expected findings for open SSH security group")
	}
}

func TestEC2Secure(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 10.0.0.0/8
`
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	resources, _, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].Type != "aws_security_group" {
		t.Fatalf("unexpected resources: %+v", resources)
	}
	v, ok := resources[0].Attributes["ingress"]
	if !ok || !v.Known {
		t.Fatalf("ingress missing")
	}
	l, _ := v.AsList()
	if len(l) != 1 {
		t.Fatalf("expected 1 ingress rule, got %d", len(l))
	}
	m, _ := l[0].AsMap()
	fp, _ := m["from_port"].AsString()
	_ = fp
	// from_port is numeric (float64 in IR)
	if f, ok := m["from_port"].Raw.(float64); !ok || f != 443 {
		t.Errorf("from_port = %v, want 443", m["from_port"].Raw)
	}
}

func TestRDSVulnerable(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      MasterUsername: admin
      MasterUserPassword: password123
      AllocatedStorage: 20
`
	findings := scanTemplate(t, "template.yaml", src)
	if len(findings) == 0 {
		t.Errorf("expected findings for unencrypted/public RDS")
	}
	ids := ruleIDs(findings)
	// StorageEncrypted absent -> encryption rule should fire (fail-closed).
	found := false
	for id := range ids {
		if strings.Contains(id, "AEGIS-AWS-") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AWS findings, got %v", ids)
	}
}

func TestRDSSecure(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      MasterUsername: admin
      ManageMasterUserPassword: true
      AllocatedStorage: 20
      StorageEncrypted: true
      BackupRetentionPeriod: 7
      DeletionProtection: true
      MultiAZ: true
`
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	resources, _, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].Type != "aws_db_instance" {
		t.Fatalf("unexpected: %+v", resources)
	}
	v, ok := resources[0].Attributes["storage_encrypted"]
	if !ok {
		t.Fatalf("storage_encrypted missing")
	}
	b, ok := v.AsBool()
	if !ok || !b {
		t.Errorf("storage_encrypted = %v", v.Raw)
	}
}

func TestIntrinsicRefParameter(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  EnvName:
    Type: String
    Default: prod
  NoDefault:
    Type: String
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref EnvName
      Tags:
        - Key: owner
          Value: !Ref NoDefault
`
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	resources, _, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	attrs := resources[0].Attributes
	bn, ok := attrs["bucket_name"]
	if !ok {
		t.Fatalf("bucket_name missing")
	}
	if s, ok := bn.AsString(); !ok || s != "prod" {
		t.Errorf("bucket_name = %v, want prod (parameter default)", bn.Raw)
	}
	tags, ok := attrs["tags"]
	if !ok {
		t.Fatalf("tags missing")
	}
	l, _ := tags.AsList()
	if len(l) != 1 {
		t.Fatalf("tags len = %d", len(l))
	}
	m, _ := l[0].AsMap()
	if m["value"].Known {
		t.Errorf("expected unknown value for param without default")
	}
	if m["value"].Ref == "" {
		t.Errorf("expected Ref set on unknown parameter value")
	}
}

func TestIntrinsicJoinSub(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Env:
    Type: String
    Default: prod
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Join ['-', ['myapp', !Ref Env]]
      Tags:
        - Key: name
          Value: !Sub '${Env}-bucket'
`
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	resources, _, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	attrs := resources[0].Attributes
	if s, ok := attrs["bucket_name"].AsString(); !ok || s != "myapp-prod" {
		t.Errorf("bucket_name = %v, want myapp-prod", attrs["bucket_name"].Raw)
	}
	tags, _ := attrs["tags"].AsList()
	m, _ := tags[0].AsMap()
	if s, ok := m["value"].AsString(); !ok || s != "prod-bucket" {
		t.Errorf("sub value = %v, want prod-bucket", m["value"].Raw)
	}
}

func TestUnknownTypeSkipped(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Weird:
    Type: AWS::Exotic::Widget
    Properties:
      Foo: bar
`
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	resources, diags, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources for unmapped type, got %d", len(resources))
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "unmapped resource type") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unmapped-type diagnostic, got %v", diags)
	}
}

func TestMalformedTemplate(t *testing.T) {
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	_, diags, err := ad.Parse(path, []byte("Resources:\n  - broken: [unclosed"))
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) == 0 {
		t.Errorf("expected error diagnostic for malformed YAML")
	}
}

func TestOutputs(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  B:
    Type: AWS::S3::Bucket
Outputs:
  BucketArn:
    Value: !GetAtt B.Arn
`
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	resources, _, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources (bucket + output), got %d", len(resources))
	}
	var out *ir.Resource
	for i := range resources {
		if resources[i].Type == "cfn_output" {
			out = &resources[i]
		}
	}
	if out == nil {
		t.Fatalf("cfn_output resource missing")
	}
	v, ok := out.Attributes["value"]
	if !ok {
		t.Fatalf("output value missing")
	}
	if v.Known {
		t.Errorf("expected GetAtt output to be unknown")
	}
}
