package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/rules"
)

// labDir is the real-world vulnerable corpus used for benchmarking.
var labDir = filepath.Join(os.Getenv("HOME"), "workspace", "terraform", "vuln-three-tier")

func BenchmarkScanLab(b *testing.B) {
	if _, err := os.Stat(labDir); err != nil {
		b.Skipf("lab corpus not present: %v", err)
	}
	registry := rules.RegistryFor("all")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, _, _, err := scanFull(labDir, defaultAdapters(), registry)
		if err != nil {
			b.Fatal(err)
		}
		if len(res.Findings) == 0 {
			b.Fatal("expected findings on the vulnerable lab")
		}
	}
}

// genSyntheticCorpus writes n resources across several .tf files into dir.
// Deterministic: violating/compliant pattern repeats every 4 resources.
func genSyntheticCorpus(t testing.TB, dir string, n int) {
	t.Helper()
	var sb strings.Builder
	perFile := 100
	for i := 0; i < n; i++ {
		switch i % 4 {
		case 0:
			fmt.Fprintf(&sb, "resource \"aws_s3_bucket\" \"b%d\" {\n  bucket = \"bench-bucket-%d\"\n}\n\n", i, i)
		case 1:
			fmt.Fprintf(&sb, "resource \"aws_security_group\" \"sg%d\" {\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n\n", i)
		case 2:
			fmt.Fprintf(&sb, "resource \"aws_db_instance\" \"db%d\" {\n  identifier          = \"bench-db-%d\"\n  engine              = \"mysql\"\n  instance_class      = \"db.t3.micro\"\n  allocated_storage   = 20\n  storage_encrypted   = %t\n  deletion_protection = true\n}\n\n", i, i, i%8 == 2)
		case 3:
			fmt.Fprintf(&sb, "resource \"aws_ebs_volume\" \"v%d\" {\n  availability_zone = \"us-east-1a\"\n  size              = 40\n  encrypted         = %t\n}\n\n", i, i%8 != 3)
		}
		if (i+1)%perFile == 0 || i == n-1 {
			path := filepath.Join(dir, fmt.Sprintf("gen_%03d.tf", i/perFile))
			if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			sb.Reset()
		}
	}
}

func BenchmarkScanLarge(b *testing.B) {
	dir := b.TempDir()
	genSyntheticCorpus(b, dir, 2000)
	registry := rules.RegistryFor("all")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, _, _, err := scanFull(dir, defaultAdapters(), registry)
		if err != nil {
			b.Fatal(err)
		}
		if len(res.Findings) == 0 {
			b.Fatal("expected findings on the synthetic corpus")
		}
	}
}
