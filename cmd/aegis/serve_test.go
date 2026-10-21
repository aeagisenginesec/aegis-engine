package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis/internal/ir"
	"aegis/internal/version"
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
	newServeMux("").ServeHTTP(rr, req)
	return rr
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()
	newServeMux("").ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "ok" || got["version"] != version.Version {
		t.Errorf("health = %v, want status ok version %s", got, version.Version)
	}
}

func TestHealthMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/health", nil)
	rr := httptest.NewRecorder()
	newServeMux("").ServeHTTP(rr, req)
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
	newServeMux("").ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestScanUnknownPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/nope", nil)
	rr := httptest.NewRecorder()
	newServeMux("").ServeHTTP(rr, req)
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

// --- Item 5: API security ---

func TestScanAuthToken(t *testing.T) {
	mux := newServeMux("s3cret-token")
	do := func(auth string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/scan", strings.NewReader(`{"files":[]}`))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := do(""); code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", code)
	}
	if code := do("Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", code)
	}
	if code := do("Bearer s3cret-token"); code != http.StatusOK {
		t.Errorf("right token: status = %d, want 200", code)
	}
	// Health stays open for liveness probes even with a token set.
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("health with token set: status = %d, want 200", rr.Code)
	}
}

func TestScanRejectsTrailingData(t *testing.T) {
	if rr := postScan(t, `{"files":[]} trailing garbage`); rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for trailing data", rr.Code)
	}
	// Trailing whitespace/newline is fine.
	if rr := postScan(t, "{\"files\":[]}\n"); rr.Code != http.StatusOK {
		t.Errorf("trailing newline: status = %d, want 200", rr.Code)
	}
}

func TestScanUnknownPathJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/nope", nil)
	rr := httptest.NewRecorder()
	newServeMux("").ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Errorf("404 body is not JSON: %v", err)
	}
}

func TestTruncateServeDiag(t *testing.T) {
	short := "small problem"
	if got := truncateServeDiag(short); got != short {
		t.Errorf("short message changed: %q", got)
	}
	long := strings.Repeat("x", maxServeDiagChars+500)
	got := truncateServeDiag(long)
	if len(got) > maxServeDiagChars+64 {
		t.Errorf("long message not truncated: %d bytes", len(got))
	}
	if !strings.HasSuffix(got, "[truncated]") {
		t.Errorf("missing truncation marker: %q", got[len(got)-20:])
	}
}

func TestServeSanitizesPanicText(t *testing.T) {
	panicErr := fmt.Errorf("adapter bicep panicked: runtime error: slice bounds out of range [:18] with length 15")
	if got := sanitizeServeParseErr(panicErr); !strings.Contains(got, "withheld") || strings.Contains(got, "slice bounds") {
		t.Errorf("panic text not sanitized: %q", got)
	}
	plainErr := fmt.Errorf("terraform: main.tf: unbalanced braces: 3 open, 1 close")
	if got := sanitizeServeParseErr(plainErr); !strings.Contains(got, "unbalanced braces") {
		t.Errorf("ordinary error changed: %q", got)
	}
	if got := sanitizeServeParseErr(nil); got != "" {
		t.Errorf("nil error: got %q", got)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

const serveVulnCFN = `
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DbPassword:
    Type: String
    Default: Sup3rSecret!-prod-2024
Resources:
  OpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: open
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
`

const serveVulnARM = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "teststore",
      "location": "westeurope",
      "sku": {"name": "Standard_LRS"},
      "kind": "StorageV2",
      "properties": {"allowBlobPublicAccess": true}
    }
  ]
}`

// TestScanInMemoryCFNParity guards the HandlesContent fix: in-memory API
// scans must route CFN/ARM bytes to their adapters (not manifests), or
// their findings are silently lost (CFN 11/14, ARM 0/35 in the old code).
func TestScanInMemoryCFNParity(t *testing.T) {
	body := `{"files": [{"path": "template.yaml", "content": ` + jsonString(serveVulnCFN) + `}], "rules": "aws"}`
	rr := postScan(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp scanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Resources == 0 {
		t.Fatalf("expected CFN resources parsed in-memory, got 0")
	}
	seen := map[string]bool{}
	for _, f := range resp.Findings {
		seen[f.RuleID] = true
	}
	if !seen["AEGIS-AWS-004"] {
		t.Errorf("missing AEGIS-AWS-004 on in-memory CFN scan; got %v", keys(seen))
	}
	// AEGIS-AWS-857 needs the real CFN adapter's synthetic cfn_parameter
	// resources; the manifests fallback path cannot produce it.
	if !seen["AEGIS-AWS-857"] {
		t.Errorf("missing AEGIS-AWS-857 on in-memory CFN scan; got %v", keys(seen))
	}
}

func TestScanInMemoryARMParity(t *testing.T) {
	body := `{"files": [{"path": "azuredeploy.json", "content": ` + jsonString(serveVulnARM) + `}], "rules": "azure"}`
	rr := postScan(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp scanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Resources == 0 {
		t.Fatalf("expected ARM resources parsed in-memory, got 0")
	}
	seen := map[string]bool{}
	for _, f := range resp.Findings {
		seen[f.RuleID] = true
	}
	if !seen["AEGIS-AZR-001"] {
		t.Errorf("missing AEGIS-AZR-001 on in-memory ARM scan; got %v", keys(seen))
	}
}
