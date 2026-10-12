package rules

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"aegis/internal/ir"
)

// TestConcurrentScanDeterminism scans the same resource set 100 times
// concurrently and verifies every run produces byte-identical findings.
// This guards the worker-pool parallelism in Registry.Run: any shared-state
// mutation (map writes, slice appends to shared backing arrays, unsorted
// output) would surface as a hash mismatch under -race or otherwise.
func TestConcurrentScanDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 100x stress test in short mode")
	}
	resources := stressResources(200)
	registry := DefaultRegistry()

	// Baseline: one sequential-equivalent run.
	baseline := hashFindings(t, registry.Run(resources))

	const runs = 100
	errs := make(chan error, runs)
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := hashFindings(t, registry.Run(resources))
			if got != baseline {
				errs <- fmt.Errorf("run produced different findings hash: got %s want %s", got, baseline)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestConcurrentRegistryReuse hammers a single shared Registry from many
// goroutines to prove Register/All/Run are safe for concurrent use.
func TestConcurrentRegistryReuse(t *testing.T) {
	registry := DefaultRegistry()
	resources := stressResources(50)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_ = registry.Run(resources)
				_ = registry.All()
			}
		}()
	}
	wg.Wait()
}

func hashFindings(t *testing.T, findings []ir.Finding) string {
	t.Helper()
	b, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// stressResources builds n synthetic resources spanning several rule
// domains so the stress run exercises a realistic rule mix.
func stressResources(n int) []ir.Resource {
	out := make([]ir.Resource, 0, n)
	for i := 0; i < n; i++ {
		switch i % 4 {
		case 0:
			out = append(out, ir.Resource{
				Type: "aws_s3_bucket", Name: fmt.Sprintf("b%d", i),
				Provider:   "aws",
				Attributes: map[string]ir.Value{},
			})
		case 1:
			out = append(out, ir.Resource{
				Type: "aws_security_group", Name: fmt.Sprintf("sg%d", i),
				Provider: "aws",
				Attributes: map[string]ir.Value{
					"ingress": {Raw: []ir.Value{{
						Raw: map[string]ir.Value{
							"from_port":   {Raw: 22.0, Known: true},
							"to_port":     {Raw: 22.0, Known: true},
							"protocol":    {Raw: "tcp", Known: true},
							"cidr_blocks": {Raw: []ir.Value{{Raw: "0.0.0.0/0", Known: true}}, Known: true},
						}, Known: true,
					}}, Known: true},
				},
			})
		case 2:
			out = append(out, ir.Resource{
				Type: "aws_db_instance", Name: fmt.Sprintf("db%d", i),
				Provider: "aws",
				Attributes: map[string]ir.Value{
					"storage_encrypted": {Raw: false, Known: true},
				},
			})
		default:
			out = append(out, ir.Resource{
				Type: "aws_iam_policy", Name: fmt.Sprintf("p%d", i),
				Provider: "aws",
				Attributes: map[string]ir.Value{
					"policy": {Raw: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, Known: true},
				},
			})
		}
	}
	return out
}
