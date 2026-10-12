package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"aegis/internal/adapter/terraform"
	"aegis/internal/discovery"
	"aegis/internal/ir"
	"aegis/internal/rules"
	"aegis/internal/semantics"
)

func main() {
	target := "/tmp/p6/large"
	files, err := discovery.Discover(target)
	if err != nil {
		panic(err)
	}
	type pr struct{ mod *terraform.Module }
	results := make([]pr, len(files))
	workers := runtime.NumCPU()
	jobs := make(chan int, len(files))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				f := files[idx]
				ta := terraform.New()
				if !ta.Handles(f.Path) {
					continue
				}
				src, err := discovery.Read(f)
				if err != nil {
					continue
				}
				mod, _, perr := ta.ParseModule(f.Path, src)
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
	fmt.Printf("resources=%d\n", len(resources))
	for it := 0; it < 3; it++ {
		t := time.Now()
		reg := rules.RegistryFor("all")
		f := reg.Run(resources)
		fmt.Printf("iter %d: fresh-registry Run = %.1f ms findings=%d\n",
			it, float64(time.Since(t).Nanoseconds())/1e6, len(f))
	}
}
