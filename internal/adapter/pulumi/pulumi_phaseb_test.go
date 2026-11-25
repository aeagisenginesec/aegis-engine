package pulumi

import (
	"testing"
)

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
