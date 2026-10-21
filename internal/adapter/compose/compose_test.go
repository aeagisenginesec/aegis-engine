package compose

import (
	"strings"
	"testing"
)

func TestHandles(t *testing.T) {
	a := Adapter{}
	for _, p := range []string{
		"docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml",
		"dir/docker-compose.yml", "docker-compose.prod.yml",
		"app.compose.yaml",
	} {
		if !a.Handles(p) {
			t.Errorf("Handles(%q) = false, want true", p)
		}
	}
	for _, p := range []string{
		"a.tf", "values.yaml", "deployment.yml", "Dockerfile", "a.json",
	} {
		if a.Handles(p) {
			t.Errorf("Handles(%q) = true, want false", p)
		}
	}
}

const sampleCompose = `
services:
  web:
    image: nginx:1.25.3
    privileged: true
    cap_add:
      - SYS_ADMIN
      - NET_RAW
    network_mode: host
    user: "1000"
    ports:
      - "8080:80"
      - 443:443
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /data/app:/app
      - type: bind
        source: /srv/static
        target: /static
    environment:
      DB_PASSWORD: s3cr3t
      APP_ENV: production
      DEBUG: "true"
  worker:
    image: myapp:latest
    environment:
      - API_KEY=abc123
      - LOG_LEVEL=info
`

func TestParseServices(t *testing.T) {
	a := New()
	rs, diags, err := a.Parse("docker-compose.yml", []byte(sampleCompose))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %+v", diags)
	}
	if len(rs) != 2 {
		t.Fatalf("expected 2 services, got %d", len(rs))
	}
	web := rs[0]
	if web.Type != "compose_service" || web.Name != "web" {
		t.Fatalf("bad identity: %s/%s", web.Type, web.Name)
	}
	strAttr := func(name string) string {
		v, ok := web.Attributes[name]
		if !ok {
			return "<absent>"
		}
		s, _ := v.AsString()
		return s
	}
	if strAttr("image") != "nginx:1.25.3" {
		t.Errorf("image = %q", strAttr("image"))
	}
	if b, _ := web.Attributes["privileged"].AsBool(); !b {
		t.Error("privileged should be true")
	}
	if strAttr("network_mode") != "host" {
		t.Errorf("network_mode = %q", strAttr("network_mode"))
	}
	if strAttr("user") != "1000" {
		t.Errorf("user = %q", strAttr("user"))
	}
	// Volumes: docker.sock, /data/app, /srv/static.
	vols, _ := web.Attributes["volumes"].AsList()
	if len(vols) != 3 {
		t.Fatalf("expected 3 volumes, got %d", len(vols))
	}
	var volStrs []string
	for _, v := range vols {
		s, _ := v.AsString()
		volStrs = append(volStrs, s)
	}
	for _, want := range []string{"/var/run/docker.sock", "/data/app", "/srv/static"} {
		found := false
		for _, s := range volStrs {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Errorf("volume %q not captured (got %v)", want, volStrs)
		}
	}
	// Secret env: DB_PASSWORD only (APP_ENV/DEBUG are not secrets).
	secrets, _ := web.Attributes["env_secrets"].AsList()
	if len(secrets) != 1 {
		t.Fatalf("expected 1 env secret, got %d", len(secrets))
	}
	m, _ := secrets[0].AsMap()
	nm, _ := m["name"].AsString()
	if nm != "DB_PASSWORD" {
		t.Errorf("secret name = %q", nm)
	}
	for _, v := range web.Attributes {
		if s, ok := v.Raw.(string); ok && strings.Contains(s, "s3cr3t") {
			t.Errorf("secret value leaked in attribute %q", s)
		}
	}

	worker := rs[1]
	wsecrets, _ := worker.Attributes["env_secrets"].AsList()
	if len(wsecrets) != 1 {
		t.Fatalf("worker: expected 1 env secret, got %d", len(wsecrets))
	}
	if _, ok := worker.Attributes["user"]; ok {
		t.Error("worker has no user; attribute should be absent")
	}
}

func TestParseMalformed(t *testing.T) {
	a := New()
	rs, diags, err := a.Parse("docker-compose.yml", []byte("services: [unclosed\n"))
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(rs) != 0 {
		t.Fatalf("expected no resources, got %d", len(rs))
	}
	if len(diags) == 0 {
		t.Fatal("expected a diagnostic for malformed YAML")
	}
}

func TestParseNoServices(t *testing.T) {
	a := New()
	rs, diags, err := a.Parse("docker-compose.yml", []byte("version: \"3\"\n"))
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if len(rs) != 0 || len(diags) == 0 {
		t.Fatalf("expected warning diag and no resources, got %d/%d", len(rs), len(diags))
	}
}

// Parity (item 2): an unknown service key must produce a warning
// diagnostic, never vanish silently. A typo'd security key
// (priviliged) is the motivating case: without the warning, a
// privileged container scans clean.
func TestUnknownServiceKeyWarns(t *testing.T) {
	a := New()
	src := "services:\n  app:\n    image: ubuntu:latest\n    priviliged: true\n    user: \"0\"\n"
	_, diags, err := a.Parse("docker-compose.yml", []byte(src))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Level == "warning" && strings.Contains(d.Message, "priviliged") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning diagnostic for unknown key priviliged, got %v", diags)
	}
	// Known keys (including x-* extensions) stay silent.
	src2 := "services:\n  app:\n    image: ubuntu:latest\n    restart: unless-stopped\n    x-custom: true\n"
	_, diags2, err := a.Parse("docker-compose.yml", []byte(src2))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(diags2) != 0 {
		t.Errorf("expected no diagnostics for known keys, got %v", diags2)
	}
}
