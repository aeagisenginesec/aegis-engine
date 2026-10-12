package manifests

import (
	"strings"
	"testing"

	"aegis/internal/ir"
	"aegis/internal/rules/aws"
)

func mustParse(t *testing.T, path, src string) ([]ir.Resource, []ir.Diagnostic) {
	t.Helper()
	rs, diags, err := Adapter{}.Parse(path, []byte(src))
	if err != nil {
		t.Fatalf("Parse(%s) hard error: %v", path, err)
	}
	return rs, diags
}

func byAddress(rs []ir.Resource) map[string]ir.Resource {
	m := make(map[string]ir.Resource, len(rs))
	for _, r := range rs {
		m[r.Address()] = r
	}
	return m
}

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

func TestHandles(t *testing.T) {
	a := Adapter{}
	for _, p := range []string{"a.yaml", "a.yml", "a.YAML", "dir/b.json", "TEMPLATE.JSON"} {
		if !a.Handles(p) {
			t.Errorf("Handles(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"a.tf", "a.plan.json", "dir/x.plan.JSON", "a.txt", "a"} {
		if a.Handles(p) {
			t.Errorf("Handles(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Kubernetes
// ---------------------------------------------------------------------------

const k8sMultiDoc = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.25
        securityContext:
          privileged: true
---
apiVersion: v1
kind: Service
metadata:
  name: web-svc
spec:
  ports:
  - port: 80
`

func TestParseK8sMultiDoc(t *testing.T) {
	rs, diags := mustParse(t, "app.yaml", k8sMultiDoc)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if len(rs) != 2 {
		t.Fatalf("got %d resources, want 2", len(rs))
	}
	if rs[0].Type != "k8s_Deployment" || rs[0].Name != "web" || rs[0].Provider != "k8s" {
		t.Errorf("unexpected first resource: %+v", rs[0])
	}
	if rs[1].Type != "k8s_Service" || rs[1].Name != "web-svc" {
		t.Errorf("unexpected second resource: %+v", rs[1])
	}
	// Whole document becomes attributes.
	spec, ok := rs[0].Attributes["spec"].AsMap()
	if !ok {
		t.Fatalf("Deployment has no spec map: %+v", rs[0].Attributes["spec"])
	}
	tmpl, ok := spec["template"].AsMap()
	if !ok {
		t.Fatalf("no template map")
	}
	pspec, ok := tmpl["spec"].AsMap()
	if !ok {
		t.Fatalf("no pod spec map")
	}
	cl, ok := pspec["containers"].AsList()
	if !ok || len(cl) != 1 {
		t.Fatalf("containers not a 1-list: %+v", pspec["containers"])
	}
	cm, ok := cl[0].AsMap()
	if !ok {
		t.Fatalf("container not a map")
	}
	sc, ok := cm["securityContext"].AsMap()
	if !ok {
		t.Fatalf("no securityContext map")
	}
	if b, ok := sc["privileged"].AsBool(); !ok || !b {
		t.Errorf("privileged not known true: %+v", sc["privileged"])
	}
}

func TestParseK8sUnnamed(t *testing.T) {
	rs, _ := mustParse(t, "x.yaml", "apiVersion: v1\nkind: ConfigMap\ndata:\n  k: v\n")
	if len(rs) != 1 || rs[0].Name != "unnamed" {
		t.Fatalf("expected unnamed resource, got %+v", rs)
	}
}

func TestParseUnrecognizedDoc(t *testing.T) {
	rs, diags := mustParse(t, "x.yaml", "foo: bar\nbaz: 1\n")
	if len(rs) != 0 {
		t.Fatalf("expected no resources, got %d", len(rs))
	}
	if len(diags) != 1 || diags[0].Level != "warning" || !strings.Contains(diags[0].Message, "unrecognized") {
		t.Fatalf("expected one unrecognized warning, got %+v", diags)
	}
}

func TestParseMalformedYAML(t *testing.T) {
	rs, diags := mustParse(t, "x.yaml", "apiVersion: [unclosed\n  bad: : :\n")
	if len(rs) != 0 {
		t.Fatalf("expected no resources, got %d", len(rs))
	}
	if len(diags) != 1 || diags[0].Level != "error" {
		t.Fatalf("expected one error diagnostic, got %+v", diags)
	}
}

// ---------------------------------------------------------------------------
// CloudFormation
// ---------------------------------------------------------------------------

const cfnTemplate = `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "EnvName": {"Type": "String", "Default": "prod"},
    "NoDefault": {"Type": "String"}
  },
  "Resources": {
    "DataBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": {"Ref": "EnvName"},
        "AccessControl": "Private",
        "Joined": {"Fn::Join": ["-", ["a", "b"]]},
        "Missing": {"Ref": "DoesNotExist"}
      }
    },
    "MainDB": {
      "Type": "AWS::RDS::DBInstance",
      "Properties": {
        "StorageEncrypted": false,
        "PubliclyAccessible": {"Ref": "NoDefault"},
        "DBInstanceClass": "db.t3.micro"
      }
    },
    "OpenSG": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "open",
        "SecurityGroupIngress": [
          {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}
        ]
      }
    },
    "BucketPolicy": {
      "Type": "AWS::S3::BucketPolicy",
      "Properties": {
        "Bucket": {"Ref": "DataBucket"},
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]
        }
      }
    }
  }
}`

func TestParseCFN(t *testing.T) {
	rs, diags := mustParse(t, "infra.json", cfnTemplate)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	m := byAddress(rs)
	if len(m) != 4 {
		t.Fatalf("got %d resources, want 4: %v", len(m), rs)
	}

	// S3 bucket: no BucketEncryption -> absent attribute (rule 001 fires).
	bkt := m["aws_s3_bucket.DataBucket"]
	if _, ok := bkt.Attributes["server_side_encryption_configuration"]; ok {
		t.Errorf("encryption attribute should be absent")
	}
	if s, ok := bkt.Attributes["acl"].AsString(); !ok || s != "private" {
		t.Errorf("acl = %v, want private", bkt.Attributes["acl"])
	}
	// Ref to parameter with Default resolves.
	if s, ok := bkt.Attributes["bucket_name"].AsString(); !ok || s != "prod" {
		t.Errorf("bucket_name = %v, want prod", bkt.Attributes["bucket_name"])
	}
	// Fn::Join -> unknown.
	if v := bkt.Attributes["joined"]; v.Known {
		t.Errorf("Fn::Join should be unknown: %+v", v)
	}
	// Ref to unknown name -> unknown with no Ref.
	if v := bkt.Attributes["missing"]; v.Known || v.IsRef() {
		t.Errorf("Ref to unknown should be plain unknown: %+v", v)
	}

	// RDS: StorageEncrypted false is known false.
	db := m["aws_db_instance.MainDB"]
	if b, ok := db.Attributes["storage_encrypted"].AsBool(); !ok || b {
		t.Errorf("storage_encrypted = %v, want known false", db.Attributes["storage_encrypted"])
	}
	// Ref to parameter without Default -> unknown.
	if v := db.Attributes["publicly_accessible"]; v.Known {
		t.Errorf("Ref to defaultless parameter should be unknown: %+v", v)
	}
	// Unmapped property passes through verbatim, snake_cased.
	if s, ok := db.Attributes["db_instance_class"].AsString(); !ok || s != "db.t3.micro" {
		t.Errorf("db_instance_class = %v", db.Attributes["db_instance_class"])
	}

	// Security group ingress shape matches the rule pack.
	sg := m["aws_security_group.OpenSG"]
	ing, ok := sg.Attributes["ingress"].AsList()
	if !ok || len(ing) != 1 {
		t.Fatalf("ingress not a 1-list: %+v", sg.Attributes["ingress"])
	}
	im, ok := ing[0].AsMap()
	if !ok {
		t.Fatalf("ingress element not a map")
	}
	cidrs, ok := im["cidr_blocks"].AsList()
	if !ok || len(cidrs) != 1 {
		t.Fatalf("cidr_blocks wrong: %+v", im["cidr_blocks"])
	}
	if s, ok := cidrs[0].AsString(); !ok || s != "0.0.0.0/0" {
		t.Errorf("cidr = %v", cidrs[0])
	}

	// BucketPolicy: Bucket Ref resolves to the bucket; policy is JSON text.
	pol := m["aws_s3_bucket_policy.BucketPolicy"]
	if v := pol.Attributes["bucket"]; !v.IsRef() || v.Ref != "aws_s3_bucket.DataBucket" {
		t.Errorf("bucket ref = %+v, want aws_s3_bucket.DataBucket", v)
	}
	ps, ok := pol.Attributes["policy"].AsString()
	if !ok || !strings.Contains(ps, "s3:GetObject") {
		t.Errorf("policy not JSON with s3:GetObject: %v", pol.Attributes["policy"])
	}
}

// TestCFNInterop proves the normalized output feeds the real AWS rule pack:
// the unencrypted bucket must trip AEGIS-AWS-001 and the open SG 004.
func TestCFNInterop(t *testing.T) {
	rs, _ := mustParse(t, "infra.json", cfnTemplate)
	fired := map[string]bool{}
	for _, rule := range aws.Rules() {
		for _, r := range rs {
			if !rule.AppliesTo(r.Type) {
				continue
			}
			for range rule.Check(r) {
				fired[rule.ID()] = true
			}
		}
	}
	for _, id := range []string{"AEGIS-AWS-001", "AEGIS-AWS-004", "AEGIS-AWS-007"} {
		if !fired[id] {
			t.Errorf("rule %s did not fire on CFN output", id)
		}
	}
}

func TestCFNEncryptedBucketQuiet(t *testing.T) {
	tpl := `{"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {
    "BucketEncryption": {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
    "VersioningConfiguration": {"Status": "Enabled"},
    "LoggingConfiguration": {"DestinationBucketName": "log-bucket", "LogFilePrefix": "b/"}}}}}`
	rs, _ := mustParse(t, "b.json", tpl)
	if len(rs) != 1 {
		t.Fatalf("got %d resources", len(rs))
	}
	bkt := rs[0]
	if v, ok := bkt.Attributes["server_side_encryption_configuration"]; !ok || !v.Known {
		t.Errorf("encryption marker should be present+known: %+v", v)
	}
	vm, ok := bkt.Attributes["versioning"].AsMap()
	if !ok {
		t.Fatalf("versioning not a map: %+v", bkt.Attributes["versioning"])
	}
	if b, ok := vm["enabled"].AsBool(); !ok || !b {
		t.Errorf("versioning.enabled = %v", vm["enabled"])
	}
	for _, rule := range aws.Rules() {
		if !rule.AppliesTo(bkt.Type) {
			continue
		}
		// Hygiene rules (Low severity) may fire on operational gaps like
		// missing lifecycle/replication; only security rules must stay quiet.
		if rule.Severity() == ir.SeverityLow {
			continue
		}
		if fs := rule.Check(bkt); len(fs) != 0 {
			t.Errorf("rule %s fired on encrypted+versioned bucket: %+v", rule.ID(), fs)
		}
	}
}

func TestCFNGetAtt(t *testing.T) {
	tpl := `{"Resources": {
    "B": {"Type": "AWS::S3::Bucket", "Properties": {}},
    "P": {"Type": "AWS::S3::BucketPolicy", "Properties": {
      "Bucket": {"Fn::GetAtt": ["B", "Arn"]},
      "PolicyDocument": {"Version": "2012-10-17"}}}}}`
	rs, _ := mustParse(t, "g.json", tpl)
	m := byAddress(rs)
	v := m["aws_s3_bucket_policy.P"].Attributes["bucket"]
	if !v.IsRef() || v.Ref != "aws_s3_bucket.B" {
		t.Errorf("Fn::GetAtt ref = %+v", v)
	}
}

func TestNormalizeType(t *testing.T) {
	if normalizeType("AWS::S3::Bucket") != "aws_s3_bucket" {
		t.Errorf("table miss")
	}
	if normalizeType("AWS::EC2::Instance") != "cfn_aws_ec2_instance" {
		t.Errorf("fallback wrong: %s", normalizeType("AWS::EC2::Instance"))
	}
}

// ---------------------------------------------------------------------------
// Determinism & robustness
// ---------------------------------------------------------------------------

func TestDeterminism(t *testing.T) {
	a := Adapter{}
	r1, d1, _ := a.Parse("a.yaml", []byte(k8sMultiDoc))
	r2, d2, _ := a.Parse("a.yaml", []byte(k8sMultiDoc))
	if len(r1) != len(r2) || len(d1) != len(d2) {
		t.Fatalf("non-deterministic parse")
	}
	for i := range r1 {
		if r1[i].Address() != r2[i].Address() {
			t.Fatalf("order changed: %s vs %s", r1[i].Address(), r2[i].Address())
		}
	}
	// CFN resource order is sorted by logical ID regardless of JSON order.
	c1, _, _ := a.Parse("c.json", []byte(cfnTemplate))
	c2, _, _ := a.Parse("c.json", []byte(cfnTemplate))
	for i := range c1 {
		if c1[i].Address() != c2[i].Address() {
			t.Fatalf("CFN order changed")
		}
	}
}

func TestNoPanicSweep(t *testing.T) {
	a := Adapter{}
	inputs := []string{
		"",
		"---\n---\n",
		"[]",
		"[1,2]",
		"just a string",
		"123",
		"null",
		`{"Resources": null}`,
		`{"Resources": {"B": null}}`,
		`{"Resources": {"B": {"Type": 42}}}`,
		`{"Parameters": {"P": {"Default": {"Fn::Join": ["-", "x"]}}}}`,
		"apiVersion: 42\nkind: [x]\n",
	}
	for _, in := range inputs {
		for _, path := range []string{"f.yaml", "f.json"} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic on %q (%s): %v", in, path, r)
					}
				}()
				_, _, _ = a.Parse(path, []byte(in))
			}()
		}
	}
}
