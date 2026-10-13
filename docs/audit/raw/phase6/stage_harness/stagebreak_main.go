// Stage-timing harness for the Aegis Phase 6 audit.
//
// Replicates the production scan pipeline (cmd/aegis scanFull + runScan
// post-processing) with per-stage wall-time measurement. Lives in /tmp:
// NOTHING here modifies the repo.
//
// Stages:
//  1. discovery  - discovery.Discover
//  2. parse      - concurrent per-file parse (NumCPU workers, same as prod)
//  3. semantics  - MergeModules + ResolveResources + ExpandDynamicBlocks + ExpandModules
//  4. rules      - RegistryFor("all").Run + EnrichCompliance
//  5. report     - report.WriteJSON to io.Discard
//
// Usage: stagebreak <target> [iterations]
//go:build ignore

package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"aegis/internal/adapter/arm"
	"aegis/internal/adapter/bicep"
	"aegis/internal/adapter/cloudformation"
	"aegis/internal/adapter/compose"
	"aegis/internal/adapter/dockerfile"
	"aegis/internal/adapter/manifests"
	"aegis/internal/adapter/planjson"
	"aegis/internal/adapter/pulumi"
	"aegis/internal/adapter/terraform"
	"aegis/internal/discovery"
	"aegis/internal/ir"
	"aegis/internal/report"
	"aegis/internal/rules"
	"aegis/internal/semantics"
)

type fileParseResult struct {
	mod         *terraform.Module
	resources   []ir.Resource
	adapterName string
}

func parseOneFile(f discovery.File, adapters []ir.Adapter) fileParseResult {
	var pr fileParseResult
	var ad ir.Adapter
	for _, a := range adapters {
		if a.Handles(f.Path) {
			ad = a
			break
		}
	}
	if ad == nil {
		return pr
	}
	src, err := discovery.Read(f)
	if err != nil {
		return pr
	}
	pr.adapterName = ad.Name()
	if ta, ok := ad.(*terraform.Adapter); ok {
		mod, _, perr := ta.ParseModule(f.Path, src)
		if perr != nil {
			return pr
		}
		pr.mod = &mod
		return pr
	}
	rs, _, perr := ad.Parse(f.Path, src)
	if perr != nil {
		return pr
	}
	pr.resources = rs
	return pr
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: stagebreak <target> [iterations]")
		os.Exit(2)
	}
	target := os.Args[1]
	iters := 5
	if len(os.Args) > 2 {
		if n, err := strconv.Atoi(os.Args[2]); err == nil && n > 0 {
			iters = n
		}
	}
	adapters := []ir.Adapter{terraform.New(), planjson.Adapter{}, compose.New(), pulumi.Adapter{}, arm.New(), bicep.New(), cloudformation.New(), manifests.Adapter{}, dockerfile.New()}

	stageNames := []string{"discovery_ms", "parse_ms", "semantics_ms", "rules_ms", "report_ms"}
	all := make([][]float64, len(stageNames))
	var nFiles, nResources, nFindings int

	for it := 0; it < iters; it++ {
		var st [5]time.Duration

		t := time.Now()
		files, err := discovery.Discover(target)
		st[0] = time.Since(t)
		if err != nil {
			fmt.Fprintln(os.Stderr, "discover:", err)
			os.Exit(1)
		}

		t = time.Now()
		results := make([]fileParseResult, len(files))
		workers := runtime.NumCPU()
		if workers > len(files) {
			workers = len(files)
		}
		jobs := make(chan int, len(files))
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range jobs {
					results[idx] = parseOneFile(files[idx], adapters)
				}
			}()
		}
		for i := range files {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		st[1] = time.Since(t)

		t = time.Now()
		var resources []ir.Resource
		var mods []terraform.Module
		tfAdapter, _ := adapters[0].(*terraform.Adapter)
		for _, pr := range results {
			if pr.mod != nil {
				mods = append(mods, *pr.mod)
				resources = append(resources, pr.mod.Resources...)
				resources = append(resources, pr.mod.SyntheticResources...)
				continue
			}
			resources = append(resources, pr.resources...)
		}
		if len(mods) > 0 {
			scope := semantics.MergeModules(mods)
			resources = scope.ResolveResources(resources)
			var dynDiags []ir.Diagnostic
			resources, dynDiags = scope.ExpandDynamicBlocks(resources)
			_ = dynDiags
			expanded, _ := semantics.ExpandModules(target, mods, tfAdapter, 2)
			resources = append(resources, expanded...)
		}
		st[2] = time.Since(t)

		t = time.Now()
		registry := rules.RegistryFor("all")
		findings := registry.Run(resources)
		findings = rules.EnrichCompliance(findings)
		st[3] = time.Since(t)

		t = time.Now()
		res := ir.ScanResult{Target: target, Findings: findings, Resources: len(resources)}
		if err := report.WriteJSON(io.Discard, res); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			os.Exit(1)
		}
		st[4] = time.Since(t)

		for s := range stageNames {
			all[s] = append(all[s], float64(st[s].Nanoseconds())/1e6)
		}
		nFiles, nResources, nFindings = len(files), len(resources), len(findings)
	}

	median := func(v []float64) float64 {
		s := append([]float64(nil), v...)
		sort.Float64s(s)
		m := len(s) / 2
		if len(s)%2 == 0 {
			return (s[m-1] + s[m]) / 2
		}
		return s[m]
	}
	fmt.Printf("target=%s iters=%d files=%d resources=%d findings=%d\n", target, iters, nFiles, nResources, nFindings)
	total := 0.0
	for s, name := range stageNames {
		m := median(all[s])
		total += m
		fmt.Printf("  %-14s median %9.2f ms\n", name, m)
	}
	fmt.Printf("  %-14s median %9.2f ms\n", "TOTAL", total)
}
