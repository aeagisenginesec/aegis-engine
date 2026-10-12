package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis/internal/ir"
)

const serveVulnTF = `
resource "aws_s3_bucket" "data" {
  bucket = "example"
}

resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`

func postScan(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	newServeMux().ServeHTTP(rr, req)
	return rr
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()
	newServeMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "ok" || got["version"] != "1.0.0" {
		t.Errorf("health = %v, want status ok version 0.1.0", got)
	}
}

func TestHealthMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/health", nil)
	rr := httptest.NewRecorder()
	newServeMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestScanVulnerableTF(t *testing.T) {
	body := `{"files": [{"path": "main.tf", "content": ` + jsonString(serveVulnTF) + `}], "rules": "aws"}`
	rr := postScan(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp scanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Resources != 2 {
		t.Errorf("resources = %d, want 2", resp.Resources)
	}
	if len(resp.Findings) == 0 {
		t.Fatal("expected findings, got none")
	}
	seen := map[string]bool{}
	for _, f := range resp.Findings {
		seen[f.RuleID] = true
	}
	// S3 without encryption and open ingress must fire.
	if !seen["AEGIS-AWS-001"] {
		t.Errorf("missing AEGIS-AWS-001; got %v", keys(seen))
	}
	if !seen["AEGIS-AWS-004"] {
		t.Errorf("missing AEGIS-AWS-004; got %v", keys(seen))
	}
}

func TestScanDefaultsRules(t *testing.T) {
	// "rules" omitted: defaults to aws.
	body := `{"files": [{"path": "main.tf", "content": ` + jsonString(serveVulnTF) + `}]}`
	rr := postScan(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestScanBadRuleset(t *testing.T) {
	body := `{"files": [], "rules": "nope"}`
	if rr := postScan(t, body); rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestScanInvalidJSON(t *testing.T) {
	if rr := postScan(t, "{not json"); rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestScanMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/scan", nil)
	rr := httptest.NewRecorder()
	newServeMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestScanUnknownPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/nope", nil)
	rr := httptest.NewRecorder()
	newServeMux().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestScanTooManyFiles(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"files": [`)
	for i := 0; i < maxScanFiles+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"path": "a.tf", "content": ""}`)
	}
	sb.WriteString(`]}`)
	if rr := postScan(t, sb.String()); rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestScanBodyTooLarge(t *testing.T) {
	// Just over the 32 MiB cap.
	big := strings.Repeat("x", maxScanBody+1)
	body := `{"files": [{"path": "big.tf", "content": "` + big + `"}]}`
	if rr := postScan(t, body); rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rr.Code)
	}
}

func TestScanUnknownAdapterSkipped(t *testing.T) {
	body := `{"files": [{"path": "notes.txt", "content": "hello"}]}`
	rr := postScan(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp scanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Resources != 0 || len(resp.Findings) != 0 {
		t.Errorf("expected empty scan, got %+v", resp)
	}
	if len(resp.Diagnostics) == 0 {
		t.Error("expected a diagnostic for the unhandled file")
	}
}

func TestScanRedactsSecrets(t *testing.T) {
	fs := []ir.Finding{{
		RuleID:   "X",
		Severity: ir.SeverityHigh,
		Resource: "r",
		Evidence: ir.Evidence{Attribute: "db_password", Actual: "hunter2"},
	}}
	got := redactServeFindings(fs)
	if got[0].Evidence.Actual != "[REDACTED]" {
		t.Errorf("actual = %q, want [REDACTED]", got[0].Evidence.Actual)
	}
	// Original slice must be untouched (redaction works on copies).
	if fs[0].Evidence.Actual != "hunter2" {
		t.Errorf("input mutated: %q", fs[0].Evidence.Actual)
	}
}

func TestScanSemanticsResolve(t *testing.T) {
	// Variable indirection must resolve in-memory, like the CLI.
	tf := `
variable "cidr" { default = "0.0.0.0/0" }
resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.cidr]
  }
}
`
	body := `{"files": [{"path": "main.tf", "content": ` + jsonString(tf) + `}]}`
	rr := postScan(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp scanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, f := range resp.Findings {
		if f.RuleID == "AEGIS-AWS-004" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AEGIS-AWS-004 via var resolution, got %+v", resp.Findings)
	}
}

// jsonString JSON-encodes s as a string literal for embedding in test bodies.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
