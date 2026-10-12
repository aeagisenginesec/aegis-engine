// Command surface for `aegis serve`: a small HTTP API over the scan
// pipeline, stdlib net/http only.
//
// Endpoints:
//
//	GET  /v1/health -> {"status":"ok","version":"1.0.0"}
//	POST /v1/scan   -> {"files":[{"path":"main.tf","content":"..."}],"rules":"aws"}
//	                   runs the full in-memory pipeline (no disk writes) and
//	                   returns {"resources":n,"findings":[...],"diagnostics":[...]}
//
// Bounds: request bodies capped at 32 MiB, at most 1000 files per request,
// per-request timeout of 60s. Module expansion (which needs a directory on
// disk) is skipped for in-memory scans; variable/local resolution still
// applies. Findings are secret-redacted exactly like the CLI reports.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
	"aegis/internal/report"
	"aegis/internal/rules"
	"aegis/internal/semantics"
)

const (
	// defaultServeAddr is used when runServe gets an empty address.
	// Loopback-only by default: the API exposes scan results, so it
	// must not bind to all interfaces without an explicit choice.
	defaultServeAddr = "127.0.0.1:8734"
	// maxScanBody caps POST /v1/scan request bodies.
	maxScanBody = 32 << 20 // 32 MiB
	// maxScanFiles caps the number of files per scan request.
	maxScanFiles = 1000
	// requestTimeout bounds each request end to end.
	requestTimeout = 60 * time.Second
)

// newServeMux builds the API routes. Factored out for httptest.
func newServeMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", handleHealth)
	mux.HandleFunc("/v1/scan", handleScan)
	return mux
}

// runServe starts the HTTP API on addr (default 127.0.0.1:8734 when empty)
// and blocks until the server stops. Returns 0 on clean shutdown, 1 when
// the listener fails. Logs go to stderr via the standard log package.
func runServe(addr string) int {
	if addr == "" {
		addr = defaultServeAddr
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.TimeoutHandler(newServeMux(), requestTimeout, `{"error":"request timed out"}`),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("aegis serve: listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("aegis serve: %v", err)
		return 1
	}
	return 0
}

// handleHealth answers GET /v1/health.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	writeServeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": report.Version})
}

// scanFile is one in-memory source file in a scan request.
type scanFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// scanRequest is the POST /v1/scan body.
type scanRequest struct {
	Files []scanFile `json:"files"`
	Rules string     `json:"rules"` // "aws" (default when empty)
}

// scanResponse is the POST /v1/scan result.
type scanResponse struct {
	Resources   int             `json:"resources"`
	Findings    []ir.Finding    `json:"findings"`
	Diagnostics []ir.Diagnostic `json:"diagnostics"`
}

// handleScan answers POST /v1/scan by running the full pipeline in memory.
func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxScanBody)
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			http.Error(w, `{"error":"request body exceeds 32 MiB"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	if len(req.Files) > maxScanFiles {
		http.Error(w, `{"error":"too many files (max 1000)"}`, http.StatusBadRequest)
		return
	}
	rulesParam := req.Rules
	if rulesParam == "" {
		rulesParam = "all"
	}
	packs := strings.Split(rulesParam, ",")
	if unknown := rules.UnknownPacks(packs); len(unknown) > 0 {
		http.Error(w, `{"error":"unknown ruleset"}`, http.StatusBadRequest)
		return
	}
	resp := scanFilesInMemory(req.Files, rules.RegistryFor(packs...))
	resp.Findings = redactServeFindings(resp.Findings)
	writeServeJSON(w, http.StatusOK, resp)
}

// scanFilesInMemory runs discover-less scan pipeline over in-memory files:
// adapter selection by Handles, ParseModule for .tf (+ semantics
// variable/local resolution), planjson for .plan.json, then the default
// rule registry. Module expansion is skipped: it needs a directory on disk.
func scanFilesInMemory(files []scanFile, registry *rules.Registry) scanResponse {
	adapters := defaultAdapters()
	var resources []ir.Resource
	var mods []terraform.Module
	diags := []ir.Diagnostic{}
	for _, f := range files {
		var ad ir.Adapter
		for _, a := range adapters {
			if a.Handles(f.Path) {
				ad = a
				break
			}
		}
		if ad == nil {
			diags = append(diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("no adapter handles %s; skipped", f.Path),
				Span:    ir.Span{File: f.Path},
			})
			continue
		}
		src := []byte(f.Content)
		if ta, ok := ad.(*terraform.Adapter); ok {
			mod, d, err := safeParseModule(ta, f.Path, src)
			diags = append(diags, d...)
			if err != nil {
				diags = append(diags, ir.Diagnostic{
					Level:   "error",
					Message: fmt.Sprintf("parse failed for %s: %v", f.Path, err),
					Span:    ir.Span{File: f.Path},
				})
				continue
			}
			mods = append(mods, mod)
			resources = append(resources, mod.Resources...)
			// Synthetic terraform_* pseudo-resources (for secret-detection
			// rules 536/538/539). They carry no resolvable refs; semantic
			// resolution is a no-op for them.
			resources = append(resources, mod.SyntheticResources...)
			continue
		}
		// Non-terraform adapters (plan JSON today) go through plain Parse.
		rs, d, err := safeParse(ad, f.Path, src)
		diags = append(diags, d...)
		if err != nil {
			diags = append(diags, ir.Diagnostic{
				Level:   "error",
				Message: fmt.Sprintf("parse failed for %s: %v", f.Path, err),
				Span:    ir.Span{File: f.Path},
			})
			continue
		}
		resources = append(resources, rs...)
	}
	if len(mods) > 0 {
		scope := semantics.MergeModules(mods)
		resources = scope.ResolveResources(resources)
		expandedDyn, dynDiags := scope.ExpandDynamicBlocks(resources)
		diags = append(diags, dynDiags...)
		resources = expandedDyn
	}
	findings := registry.Run(resources)
	if findings == nil {
		findings = []ir.Finding{}
	}
	return scanResponse{
		Resources:   len(resources),
		Findings:    findings,
		Diagnostics: diags,
	}
}

// secretSubstrings mirrors report's secret-key heuristic. Duplicated here
// because report.redactFindings is unexported and serve must not change
// report's API; keep the two in sync.
var secretSubstrings = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "key"}

// redactServeFindings redacts secret-looking evidence values, mirroring
// report.redactFindings.
func redactServeFindings(fs []ir.Finding) []ir.Finding {
	out := make([]ir.Finding, 0, len(fs))
	for _, f := range fs {
		k := strings.ToLower(f.Evidence.Attribute)
		for _, sub := range secretSubstrings {
			if strings.Contains(k, sub) {
				f.Evidence.Actual = "[REDACTED]"
				break
			}
		}
		out = append(out, f)
	}
	return out
}

// writeServeJSON writes v as JSON with the given status code.
func writeServeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
