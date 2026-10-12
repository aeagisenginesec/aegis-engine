package main

import (
	"os"
	"path/filepath"
	"testing"

	"aegis/internal/rules"
)

var vuln200Dir = filepath.Join(os.Getenv("HOME"), "workspace", "terraform", "vuln-200")

func BenchmarkScanVuln200(b *testing.B) {
	if _, err := os.Stat(vuln200Dir); err != nil {
		b.Skipf("vuln-200 corpus not present: %v", err)
	}
	registry := rules.RegistryFor("all")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, _, _, err := scanFull(vuln200Dir, defaultAdapters(), registry)
		if err != nil {
			b.Fatal(err)
		}
		if len(res.Findings) == 0 {
			b.Fatal("expected findings on vuln-200")
		}
	}
}
