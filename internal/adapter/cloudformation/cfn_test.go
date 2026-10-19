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

// TestS3BucketPolicyPreservesCase: a CFN BucketPolicy PolicyDocument must
// keep IAM key casing (Statement/Principal/Action). The converter used to
// snake_case the document (statement/principal), which silently broke
// public-principal detection (AEGIS-AWS-003) and the intentionally-public
// correlation for SSE/PAB.
func TestS3BucketPolicyPreservesCase(t *testing.T) {
	src := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: data-32a737
  DataPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref DataBucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: arn:aws:s3:::data-32a737/*
`
	findings := scanTemplate(t, "template.yaml", src)
	ids := ruleIDs(findings)
	if !ids["AEGIS-AWS-003"] {
		t.Fatalf("expected AEGIS-AWS-003 on CFN public bucket policy, got %v", findings)
	}
	// The bucket is intentionally public: SSE (001) and PAB (206) must
	// stay quiet on it.
	if ids["AEGIS-AWS-001"] || ids["AEGIS-AWS-206"] {
		t.Fatalf("001/206 must stay quiet on intentionally-public CFN bucket, got %v", findings)
	}
}

// TestLambdaUrlPublic: CFN AWS::Lambda::Url with AuthType NONE must map
// to aws_lambda_function_url with authorization_type NONE so 407 fires;
// AWS_IAM stays quiet.
func TestLambdaUrlPublic(t *testing.T) {
	public := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  HookUrl:
    Type: AWS::Lambda::Url
    Properties:
      TargetFunctionArn: arn:aws:lambda:us-east-1:123456789012:function:hook
      AuthType: NONE
`
	if ids := ruleIDs(scanTemplate(t, "template.yaml", public)); !ids["AEGIS-AWS-407"] {
		t.Fatal("expected AEGIS-AWS-407 on CFN Lambda Url with AuthType NONE")
	}
	iam := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  HookUrl:
    Type: AWS::Lambda::Url
    Properties:
      TargetFunctionArn: arn:aws:lambda:us-east-1:123456789012:function:hook
      AuthType: AWS_IAM
`
	if ids := ruleIDs(scanTemplate(t, "template.yaml", iam)); ids["AEGIS-AWS-407"] {
		t.Fatal("407 must stay quiet on CFN Lambda Url with AuthType AWS_IAM")
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
	// 1 bucket + 1 synthetic cfn_parameter (EnvName has a default;
	// NoDefault has none and emits nothing).
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
	attrs := resources[0].Attributes
	bn, ok := attrs["bucket"]
	if !ok {
		t.Fatalf("bucket missing")
	}
	if s, ok := bn.AsString(); !ok || s != "prod" {
		t.Errorf("bucket = %v, want prod (parameter default)", bn.Raw)
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
	if s, ok := attrs["bucket"].AsString(); !ok || s != "myapp-prod" {
		t.Errorf("bucket = %v, want myapp-prod", attrs["bucket"].Raw)
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

// Parity (item 2): a CFN BucketPolicy linked via !Ref must attribute to
// its bucket, so the exfiltration-path rule (AWS-104) fires on a
// policy-only public grant, not just when a public ACL is also present.
func TestS3BucketPolicyRefAttribution(t *testing.T) {
	src := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: probe-policy-only
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref DataBucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: PublicRead
            Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: "arn:aws:s3:::probe-policy-only/*"
`
	findings := scanTemplate(t, "template.yaml", src)
	if !ruleIDs(findings)["AEGIS-AWS-104"] {
		t.Errorf("expected AEGIS-AWS-104 (policy-only public grant via !Ref), got %v", ruleIDs(findings))
	}
}

// Parity (item 2): a standalone AWS::S3::PublicAccessBlock resource linked
// via !Ref must attribute to its bucket, so AWS-206 stays quiet on a
// protected private bucket (previously the type was unmapped -> dropped
// with a warning -> 206 false-positive).
func TestS3PublicAccessBlockRefAttribution(t *testing.T) {
	src := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: probe-pab
  Pab:
    Type: AWS::S3::PublicAccessBlock
    Properties:
      Bucket: !Ref DataBucket
      BlockPublicAcls: true
      BlockPublicPolicy: true
      IgnorePublicAcls: true
      RestrictPublicBuckets: true
`
	findings := scanTemplate(t, "template.yaml", src)
	if ruleIDs(findings)["AEGIS-AWS-206"] {
		t.Errorf("did not expect AEGIS-AWS-206 on bucket protected by a !Ref-linked PublicAccessBlock")
	}
}

// TestDuplicateTopLevelKeys: a generated template that repeats the
// top-level "Resources:" key (empty first, real second, with Parameters
// in between) must still parse the real resources. Previously
// mappingGet returned the FIRST match (the empty block) and the adapter
// silently produced zero resources, dropping every finding in such
// templates (R4 r4049/r4058/r4059/r4064/r4067).
func TestDuplicateTopLevelKeys(t *testing.T) {
	src := `AWSTemplateFormatVersion: "2010-09-09"
Description: App stack
Resources:
Parameters:
  DbPassword:
    Type: String
    Default: Sup3rSecret!-prod-2024
    Description: Database password
Resources:
  AppDB:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      DBInstanceClass: db.t3.micro
      DBInstanceIdentifier: app-dup
      AllocatedStorage: "20"
      StorageEncrypted: true
      MasterUsername: appadmin
      MasterUserPassword: !Ref DbPassword
  DataKey:
    Type: AWS::KMS::Key
    Properties:
      Description: data-key-dup
      EnableKeyRotation: false
  HookUrl:
    Type: AWS::Lambda::Url
    Properties:
      TargetFunctionArn: arn:aws:lambda:us-east-1:123456789012:function:hook
      AuthType: NONE
`
	ids := ruleIDs(scanTemplate(t, "template.yaml", src))
	for _, want := range []string{"AEGIS-AWS-339", "AEGIS-AWS-335", "AEGIS-AWS-407"} {
		if !ids[want] {
			t.Errorf("expected %s on duplicate-Resources template, got %v", want, ids)
		}
	}
}

func TestParametersEmitSyntheticResources(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DbPassword:
    Type: String
    Default: Sup3rSecret!-prod-2024
  InstanceType:
    Type: String
    Default: t3.micro
  NoDefault:
    Type: String
Resources:
  B:
    Type: AWS::S3::Bucket
`
	ad := New()
	path := filepath.Join(t.TempDir(), "t.yaml")
	resources, _, err := ad.Parse(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var params []*ir.Resource
	for i := range resources {
		if resources[i].Type == "cfn_parameter" {
			params = append(params, &resources[i])
		}
	}
	// DbPassword + InstanceType have defaults; NoDefault must not emit.
	if len(params) != 2 {
		t.Fatalf("expected 2 cfn_parameter resources, got %d", len(params))
	}
	byName := map[string]*ir.Resource{}
	for _, p := range params {
		byName[p.Name] = p
	}
	pw := byName["DbPassword"]
	if pw == nil {
		t.Fatalf("cfn_parameter DbPassword missing")
	}
	def, ok := pw.Attributes["default"]
	if !ok || !def.Known {
		t.Fatalf("DbPassword default missing or unknown")
	}
	s, ok := def.AsString()
	if !ok || s != "Sup3rSecret!-prod-2024" {
		t.Fatalf("DbPassword default = %q, want the plaintext default", s)
	}
}

func TestHandlesContent(t *testing.T) {
	ad := New()
	cfnYAML := []byte("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n")
	if !ad.HandlesContent("template.yaml", cfnYAML) {
		t.Errorf("HandlesContent should accept CFN YAML bytes")
	}
	// Structural (no AWSTemplateFormatVersion marker).
	cfnStruct := []byte("Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: x\n")
	if !ad.HandlesContent("template.yaml", cfnStruct) {
		t.Errorf("HandlesContent should accept structural CFN YAML bytes")
	}
	plainYAML := []byte("foo: bar\nbaz: 1\n")
	if ad.HandlesContent("template.yaml", plainYAML) {
		t.Errorf("HandlesContent should reject non-CFN YAML bytes")
	}
	if ad.HandlesContent("notes.txt", cfnYAML) {
		t.Errorf("HandlesContent should reject non-template extensions")
	}
	if ad.HandlesContent("plan.plan.json", cfnYAML) {
		t.Errorf("HandlesContent should reject .plan.json")
	}
	var _ ir.ContentSniffer = ad
}
