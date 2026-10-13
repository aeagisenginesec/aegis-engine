package semantics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/adapter/terraform"
)

// Item 6b: ExpandModules must not resolve nested modules' sources against
// the scan root. A nested module calling "../secret" used to pull in a
// sibling directory of the scan target (scan-boundary escape: resources
// from outside the target appeared as module.s.* findings), plus spurious
// "cannot read directory" warnings naming the wrong path. Only root
// modules' calls are seeded; nested calls expand via recursion.
func TestItem6bNestedModuleSourceNotResolvedAgainstRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "item6b-secret-"+filepath.Base(root))
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outside)
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("main.tf", `module "m" { source = "./sub/m" }`)
	write("sub/m/main.tf", `module "s" { source = "../secret" }
resource "aws_s3_bucket" "in_m" { bucket = "in-m" }`)
	write(filepath.Join(outside, "main.tf"), `resource "aws_s3_bucket" "outside" { bucket = "outside-target" }`)

	mods := parseTree(t, root)
	res, diags := ExpandModules(root, mods, &terraform.Adapter{}, 2)
	for _, r := range res {
		if strings.Contains(r.Name, "outside") {
			t.Fatalf("scan-boundary escape: outside-target resource expanded as %q", r.Name)
		}
	}
	for _, d := range diags {
		if strings.Contains(d.Message, outside) {
			t.Fatalf("diagnostic names out-of-target path: %s", d.Message)
		}
	}
	// The legit nested resource must still expand via recursion from root.
	found := false
	for _, r := range res {
		if r.Name == "module.m.in_m" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected module.m.in_m via recursion, got %+v (diags %+v)", res, diags)
	}
}

// Item 6b: a legitimately nested chain (root -> l1 -> l2) still expands
// via recursion, with no spurious warnings about paths that were never
// actually referenced from the wrong base.
func TestItem6bNestedChainExpandsWithoutSpuriousWarnings(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("main.tf", `module "l1" { source = "./l1" }`)
	write("l1/main.tf", `resource "aws_x" "one" { v = "1" }
module "l2" { source = "./l2" }`)
	write("l1/l2/main.tf", `resource "aws_x" "two" { v = "2" }`)
	mods := parseTree(t, root)
	res, diags := ExpandModules(root, mods, &terraform.Adapter{}, 2)
	names := map[string]bool{}
	for _, r := range res {
		names[r.Name] = true
	}
	if !names["module.l1.one"] || !names["module.l1.module.l2.two"] {
		t.Fatalf("nested chain missing: %v (diags %+v)", names, diags)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "cannot read directory") {
			t.Fatalf("spurious wrong-base warning: %s", d.Message)
		}
	}
}

// parseTree parses every .tf file under dir, like a real scan does
// (parseDir in semantics_test.go only parses the root directory).
func parseTree(t *testing.T, dir string) []terraform.Module {
	t.Helper()
	var mods []terraform.Module
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".tf" {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		mod, _, err := (&terraform.Adapter{}).ParseModule(p, src)
		if err != nil {
			t.Fatal(err)
		}
		mods = append(mods, mod)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return mods
}
