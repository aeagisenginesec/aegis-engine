package pulumi

import (
	"strings"
	"testing"
)

// Phase B (Aegis-vs-Checkov mission): Pulumi adapter gaps found by
// reproducing the R2 zero-findings hole (docs/audit/11_FINAL_EVAL_REPORT.md,
// §7: zero Aegis findings on all 15 Pulumi projects c056–c070) and the R6
// Pulumi false negatives (docs/audit/raw/final-eval-r6/fn-missed-aegis.json).
//
// The R2 hole itself (template:-nested layout) was fixed in R3, but the R6
// reproduction shows the adapter still drops whole resource types and whole
// policy documents on the same project shapes:
//
//   - aws:ecr:Repository / aws:ecr:RepositoryPolicy, aws:apigateway:Method /
//     aws:apigateway:Resource, azure-native:web:WebApp and
//     azure-native:dbforpostgresql:FlexibleServer have no typemap entry, so
//     they fall back to pulumi_* types no rule matches (r6101, r6105, r6107,
//     r6113 score 0 findings despite live rules for those resources).
//   - A policy document containing the idiomatic ${resource.arn} reference
//     is left as a mapping because stringifyPolicyDoc aborts on any unknown
//     leaf (r6110 sqs-public-policy).
//   - A policy document under fn::toJSON is left wholly unknown even though
//     its argument is statically known (R2 c056 bucket-policy-public).
//
// Every test below uses the exact project shape from the failing corpus
// (field-for-field, only names/values shortened where they carry no
// signal). Each test failed before the fix and passes after it.

// TestPhaseBECRTypesMapped reproduces R6 r6113 (toplevel layout): an ECR
// repository plus a repository policy open to Principal "*". Before the
// fix both resources fell back to pulumi_aws_ecr_repository(_policy) and
// the project scanned to 0 findings although AEGIS-AWS-408
// (ecrPolicyPublic) exists for aws_ecr_repository_policy.
func TestPhaseBECRTypesMapped(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: r6113-stack
runtime: yaml
description: Pulumi service stack
resources:
  svcRepo:
    type: aws:ecr:Repository
    properties:
      name: svc-47961f
      imageScanningConfiguration:
        scanOnPush: true
  svcRepoPolicy:
    type: aws:ecr:RepositoryPolicy
    properties:
      repository: svc-47961f
      policy:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Principal: '*'
          Action:
          - ecr:BatchGetImage
          - ecr:GetDownloadUrlForLayer
`)
	if len(rs) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(rs))
	}
	repo := findResource(rs, "svcRepo")
	if repo == nil {
		t.Fatal("svcRepo missing")
	}
	if repo.Type != "aws_ecr_repository" {
		t.Errorf("svcRepo type = %q, want aws_ecr_repository", repo.Type)
	}
	pol := findResource(rs, "svcRepoPolicy")
	if pol == nil {
		t.Fatal("svcRepoPolicy missing")
	}
	if pol.Type != "aws_ecr_repository_policy" {
		t.Errorf("svcRepoPolicy type = %q, want aws_ecr_repository_policy", pol.Type)
	}
	// The policy document must reach the rules as a JSON string so the
	// public-principal check can read it.
	s, ok := attrString(t, *pol, "policy")
	if !ok {
		t.Fatalf("svcRepoPolicy policy attribute is not a string (got %T)", pol.Attributes["policy"].Raw)
	}
	if !strings.Contains(s, `"principal":"*"`) {
		t.Errorf("policy string = %s, want it to contain principal \"*\"", s)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "unmapped type") {
			t.Errorf("unexpected unmapped-type diagnostic: %s", d.Message)
		}
	}
}

// TestPhaseBAPIGatewayMethodMapped reproduces R6 r6107 (template layout):
// an API Gateway REST API with a GET method whose authorization is NONE.
// Before the fix the Method (and Resource) fell back to pulumi_* types and
// AEGIS-AWS-403 (apiGWMethodNoAuth) never saw the resource.
func TestPhaseBAPIGatewayMethodMapped(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: r6107-stack
runtime: yaml
description: Pulumi service stack
template:
  resources:
    ordersApi:
      type: aws:apigateway:RestApi
      properties:
        name: orders-3181ee
    itemsResource:
      type: aws:apigateway:Resource
      properties:
        restApi: ${ordersApi.id}
        parentId: ${ordersApi.rootResourceId}
        pathPart: items
    listMethod:
      type: aws:apigateway:Method
      properties:
        restApi: ${ordersApi.id}
        resourceId: ${itemsResource.id}
        httpMethod: GET
        authorization: NONE
`)
	if len(rs) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(rs))
	}
	m := findResource(rs, "listMethod")
	if m == nil {
		t.Fatal("listMethod missing")
	}
	if m.Type != "aws_api_gateway_method" {
		t.Errorf("listMethod type = %q, want aws_api_gateway_method", m.Type)
	}
	if s, ok := attrString(t, *m, "authorization"); !ok || s != "NONE" {
		t.Errorf("authorization = %q, %v; want NONE", s, ok)
	}
	res := findResource(rs, "itemsResource")
	if res == nil {
		t.Fatal("itemsResource missing")
	}
	if res.Type != "aws_api_gateway_resource" {
		t.Errorf("itemsResource type = %q, want aws_api_gateway_resource", res.Type)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "unmapped type") {
			t.Errorf("unexpected unmapped-type diagnostic: %s", d.Message)
		}
	}
}

// TestPhaseBWebAppMapped reproduces R6 r6101 (template layout): an
// azure-native WebApp (kind functionapp,linux) with httpsOnly: false.
// Before the fix it fell back to pulumi_azure_native_web_webapp and no
// HTTPS rule fired. The mapping follows the ARM adapter precedent
// (Microsoft.Web/sites -> azurerm_app_service), which AEGIS-AZURE-011
// covers.
func TestPhaseBWebAppMapped(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: r6101-stack
runtime: yaml
description: Pulumi service stack
template:
  resources:
    ingestApp:
      type: azure-native:web:WebApp
      properties:
        name: ingest-05a7f9
        resourceGroupName: rg-apps
        location: northeurope
        kind: functionapp,linux
        httpsOnly: false
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "azurerm_app_service" {
		t.Errorf("type = %q, want azurerm_app_service", r.Type)
	}
	v, ok := r.Attributes["https_only"]
	if !ok || !v.Known {
		t.Fatalf("https_only missing or unknown: %+v", r.Attributes["https_only"])
	}
	if b, ok := v.Raw.(bool); !ok || b {
		t.Errorf("https_only = %v, want false", v.Raw)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "unmapped type") {
			t.Errorf("unexpected unmapped-type diagnostic: %s", d.Message)
		}
	}
}

// TestPhaseBFlexibleServerMapped reproduces the R6 r6105/r6114 shape: an
// azure-native PostgreSQL Flexible Server. Before the fix it fell back to
// pulumi_azure_native_dbforpostgresql_flexibleserver, invisible to
// AEGIS-AZURE-169 (postgresFlexPublicNet). The fixture disables public
// network access, so the adapter must surface that as
// public_network_access_enabled = false (via the general azurerm_*
// enum conversion), not drop the resource.
func TestPhaseBFlexibleServerMapped(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: r6114-stack
runtime: yaml
description: Pulumi service stack
resources:
    shopDb:
      type: azure-native:dbforpostgresql:FlexibleServer
      properties:
        serverName: shop-c2722c
        resourceGroupName: rg-shop
        location: northeurope
        version: "15"
        administratorLogin: psqladmin
        storage:
          storageSizeGB: 32
        network:
          publicNetworkAccess: Disabled
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "azurerm_postgresql_flexible_server" {
		t.Errorf("type = %q, want azurerm_postgresql_flexible_server", r.Type)
	}
	v, ok := r.Attributes["public_network_access_enabled"]
	if !ok || !v.Known {
		t.Fatalf("public_network_access_enabled missing or unknown: %+v", r.Attributes["public_network_access_enabled"])
	}
	if b, ok := v.Raw.(bool); !ok || b {
		t.Errorf("public_network_access_enabled = %v, want false", v.Raw)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "unmapped type") {
			t.Errorf("unexpected unmapped-type diagnostic: %s", d.Message)
		}
	}
}

// TestPhaseBSQSPolicyWithRefStringified reproduces R6 r6110: an SQS queue
// policy whose Resource is the idiomatic ${ordersQueue.arn} reference.
// Before the fix stringifyPolicyDoc aborted on the unknown leaf, the
// policy stayed a mapping, and AEGIS-AWS-344 (sqsPolicyPublic, which
// reads a policy string) silently missed a Principal "*" Allow statement.
func TestPhaseBSQSPolicyWithRefStringified(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: r6110-stack
runtime: yaml
description: Pulumi service stack
template:
  resources:
    ordersQueue:
      type: aws:sqs:Queue
      properties:
        name: orders-d5534e
    ordersQueuePolicy:
      type: aws:sqs:QueuePolicy
      properties:
        queueUrl: ${ordersQueue.id}
        policy:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Principal: '*'
            Action:
            - sqs:SendMessage
            - sqs:ReceiveMessage
            Resource: ${ordersQueue.arn}
`)
	pol := findResource(rs, "ordersQueuePolicy")
	if pol == nil {
		t.Fatal("ordersQueuePolicy missing")
	}
	if pol.Type != "aws_sqs_queue_policy" {
		t.Errorf("type = %q, want aws_sqs_queue_policy", pol.Type)
	}
	s, ok := attrString(t, *pol, "policy")
	if !ok {
		t.Fatalf("policy attribute is not a string (got %T); unknown leaves must not abort stringification", pol.Attributes["policy"].Raw)
	}
	if !strings.Contains(s, `"principal":"*"`) {
		t.Errorf("policy string = %s, want it to contain principal \"*\"", s)
	}
	if !strings.Contains(s, `"effect":"Allow"`) {
		t.Errorf("policy string = %s, want it to contain effect Allow", s)
	}
}

// TestPhaseBFnToJSONPolicyStringified reproduces R2 c056: an S3 bucket
// policy expressed as fn::toJSON over a statically-known document (whose
// Resource is a ${...} reference). Before the fix the intrinsic was
// treated as wholly unknown, so AEGIS-AWS-003 (s3PublicPolicy) never saw
// the Principal "*" Allow statement.
func TestPhaseBFnToJSONPolicyStringified(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: public-assets
runtime: yaml
description: Public asset bucket for the docs site.
template:
  configuration:
    bucketName:
      type: String
      default: acme-docs-assets-pulumi
  resources:
    assetsBucket:
      type: aws:s3:Bucket
      properties:
        bucket: ${bucketName}
        acl: public-read
    assetsPolicy:
      type: aws:s3:BucketPolicy
      properties:
        bucket: ${assetsBucket.id}
        policy:
          fn::toJSON:
            Version: "2012-10-17"
            Statement:
              - Sid: PublicRead
                Effect: Allow
                Principal: "*"
                Action: s3:GetObject
                Resource: ${assetsBucket.arn}/*
`)
	pol := findResource(rs, "assetsPolicy")
	if pol == nil {
		t.Fatal("assetsPolicy missing")
	}
	s, ok := attrString(t, *pol, "policy")
	if !ok {
		t.Fatalf("policy attribute is not a string (got %T); fn::toJSON over a known document must resolve", pol.Attributes["policy"].Raw)
	}
	if !strings.Contains(s, `"principal":"*"`) {
		t.Errorf("policy string = %s, want it to contain principal \"*\"", s)
	}
}

// TestPhaseBUnknownPrincipalNotPublic guards the stringify tolerance:
// a policy whose Principal itself is unresolvable must NOT be reported
// as public. Unknown leaves render as "", which matches no public or
// wildcard pattern.
func TestPhaseBUnknownPrincipalNotPublic(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: x
runtime: yaml
resources:
  q:
    type: aws:sqs:Queue
    properties:
      name: q
  qp:
    type: aws:sqs:QueuePolicy
    properties:
      queueUrl: ${q.id}
      policy:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Principal: ${somePrincipal}
          Action:
          - sqs:SendMessage
          Resource: ${q.arn}
`)
	pol := findResource(rs, "qp")
	if pol == nil {
		t.Fatal("qp missing")
	}
	s, ok := attrString(t, *pol, "policy")
	if !ok {
		t.Fatalf("policy attribute is not a string (got %T)", pol.Attributes["policy"].Raw)
	}
	if strings.Contains(s, `"principal":"*"`) {
		t.Errorf("policy string = %s, must not contain a fabricated public principal", s)
	}
}

// Phase B tests: Pulumi stack-config emission (P1-7) — pulumi_config
// resources for plaintext config entries, so AEGIS-SC-010 can fire.
// `secure:` entries (encrypted by construction) are never emitted.

func TestPhaseB_StackFileConfigEmitted(t *testing.T) {
	// r6108 shape: Pulumi.dev.yaml stack file with quoted keys and
	// {value:} mappings.
	rs, _ := parse(t, "Pulumi.dev.yaml", `
name: shop
runtime: yaml
config:
  shop:dbPassword:
    value: hunter2
  shop:apiKey:
    value: ak_live_abc
  shop:region:
    value: us-east-1
  shop:encSecret:
    secure: AQIDBAUGBwg==
resources:
  bucket:
    type: aws:s3:Bucket
    properties:
      bucket: shop-data
`)
	if len(rs) != 4 {
		t.Fatalf("expected 4 resources (bucket + 3 configs; secure skipped), got %d", len(rs))
	}
	byName := map[string]bool{}
	for _, r := range rs {
		if r.Type == "pulumi_config" {
			byName[r.Name] = true
			v, ok := attrString(t, r, "value")
			if !ok || v == "" {
				t.Errorf("pulumi_config %s has no value", r.Name)
			}
		}
	}
	for _, want := range []string{"shop:dbPassword", "shop:apiKey", "shop:region"} {
		if !byName[want] {
			t.Errorf("missing pulumi_config %s", want)
		}
	}
	if byName["shop:encSecret"] {
		t.Errorf("secure: entry must not be emitted as pulumi_config")
	}
}

func TestPhaseB_RootConfigWithTemplateResources(t *testing.T) {
	// r6105 shape: config: at the document root, resources nested
	// under template:.
	rs, _ := parse(t, "Pulumi.yaml", `
name: shop
runtime: yaml
config:
  shop:dbPassword:
    value: hunter2
template:
  resources:
    bucket:
      type: aws:s3:Bucket
      properties:
        bucket: shop-data
`)
	if len(rs) != 2 {
		t.Fatalf("expected 2 resources (bucket + pulumi_config), got %d", len(rs))
	}
	cfg := findResource(rs, "shop:dbPassword")
	if cfg == nil {
		t.Fatalf("missing pulumi_config shop:dbPassword")
	}
	if cfg.Type != "pulumi_config" {
		t.Errorf("type = %q, want pulumi_config", cfg.Type)
	}
}

func TestPhaseB_ConfigDefaultForm(t *testing.T) {
	// {type:, default:} declaration form is also indexed.
	rs, _ := parse(t, "Pulumi.yaml", `
name: cfg
runtime: yaml
configuration:
  bucketName:
    type: String
    default: my-data
resources:
  data:
    type: aws:s3:Bucket
    properties:
      bucket: ${bucketName}
`)
	cfg := findResource(rs, "bucketName")
	if cfg == nil {
		t.Fatalf("missing pulumi_config bucketName from configuration default")
	}
	if v, ok := attrString(t, *cfg, "value"); !ok || v != "my-data" {
		t.Errorf("value = %q, want my-data", v)
	}
}

func TestPhaseB_HandlesStackFiles(t *testing.T) {
	a := Adapter{}
	if !a.Handles("Pulumi.dev.yaml") {
		t.Errorf("Handles(Pulumi.dev.yaml) = false, want true")
	}
	if !a.Handles("Pulumi.prod.yml") {
		t.Errorf("Handles(Pulumi.prod.yml) = false, want true")
	}
	if a.Handles("Pulumi.yaml.bak") {
		t.Errorf("Handles(Pulumi.yaml.bak) = true, want false")
	}
	if a.Handles("myPulumi.yaml") {
		t.Errorf("Handles(myPulumi.yaml) = true, want false")
	}
}
