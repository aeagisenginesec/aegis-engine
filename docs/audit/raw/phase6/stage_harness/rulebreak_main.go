// Rule-engine scaling isolator for the Aegis Phase 6 audit (/tmp only).
//
// Parses every .tf under <target> once, then times, for increasing
// resource-prefix sizes:
//   a) rules.RegistryFor("all").Run(prefix)          -- engine only
//   b) rules.EnrichCompliance(findings)              -- enrichment only
//
// Usage: rulebreak <target>
package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"aegis/internal/adapter/terraform"
	"aegis/internal/discovery"
	"aegis/internal/ir"
	"aegis/internal/rules"
	"aegis/internal/semantics"
)

func main() {
	target := os.Args[1]
	files, err := discovery.Discover(target)
	if err != nil {
		panic(err)
	}
	// Parse everything once (concurrent, like production).
	type pr struct {
		mod *terraform.Module
	}
	results := make([]pr, len(files))
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
				f := files[idx]
				var ad *terraform.Adapter
				ta := terraform.New()
				if ta.Handles(f.Path) {
					ad = ta
				}
				if ad == nil {
					continue
				}
				src, err := discovery.Read(f)
				if err != nil {
					continue
				}
				mod, _, perr := ad.ParseModule(f.Path, src)
				if perr != nil {
					continue
				}
				results[idx].mod = &mod
			}
		}()
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	var resources []ir.Resource
	var mods []terraform.Module
	for _, r := range results {
		if r.mod == nil {
			continue
		}
		mods = append(mods, *r.mod)
		resources = append(resources, r.mod.Resources...)
		resources = append(resources, r.mod.SyntheticResources...)
	}
	scope := semantics.MergeModules(mods)
	resources = scope.ResolveResources(resources)
	fmt.Printf("parsed %d files -> %d resources\n", len(files), len(resources))

	sizes := []int{250, 500, 1000, 2000, 4000}
	sizes = append(sizes, len(resources))
	registry := rules.RegistryFor("all")
	// Warm the registry caches once (production pays this inside Run).
	_ = registry.Run(resources[:100])

	median := func(v []float64) float64 {
		s := append([]float64(nil), v...)
		sort.Float64s(s)
		return s[len(s)/2]
	}
	fmt.Printf("%-10s %-12s %-12s %-10s\n", "resources", "run_ms", "enrich_ms", "findings")
	for _, n := range sizes {
		if n > len(resources) {
			continue
		}
		prefix := resources[:n]
		var runTs, enrTs []float64
		var nf int
		for it := 0; it < 5; it++ {
			t := time.Now()
			f := registry.Run(prefix)
			runTs = append(runTs, float64(time.Since(t).Nanoseconds())/1e6)
			t = time.Now()
			f = rules.EnrichCompliance(f)
			enrTs = append(enrTs, float64(time.Since(t).Nanoseconds())/1e6)
			nf = len(f)
		}
		fmt.Printf("%-10d %-12.2f %-12.2f %-10d\n", n, median(runTs), median(enrTs), nf)
	}
}
