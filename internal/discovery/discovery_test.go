package discovery

import "testing"

func TestIsExcludedGlobs(t *testing.T) {
	SetExcludePatterns([]string{"vendor/**", "*.tfvars", "docs/*.md"})
	defer SetExcludePatterns(nil)
	cases := map[string]bool{
		"/repo/vendor/lib/vuln.tf": true,
		"/repo/vendor/vuln.tf":     true,
		"vendor/vuln.tf":           true,
		"/repo/vars.tfvars":        true,
		"vars.tfvars":              true,
		"/repo/docs/readme.md":     true,
		"/repo/main.tf":            false,
		"/repo/docs/sub/deep.md":   false, // docs/*.md is single-level
		"/repo/src/vendor/x.tf":    true,  // vendor/** matches at any depth (gitignore-style)
	}
	for path, want := range cases {
		if got := IsExcluded(path); got != want {
			t.Errorf("IsExcluded(%q) = %v, want %v", path, got, want)
		}
	}
	// **/ prefix makes vendor match at any depth.
	SetExcludePatterns([]string{"**/vendor/**"})
	defer SetExcludePatterns(nil)
	if !IsExcluded("/repo/src/vendor/x.tf") {
		t.Errorf("**/vendor/** should match at any depth")
	}
}

func TestIsExcludedEmpty(t *testing.T) {
	SetExcludePatterns(nil)
	if IsExcluded("/repo/vendor/x.tf") {
		t.Errorf("no patterns: nothing should be excluded")
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := map[string]struct {
		pat     string
		match   []string
		nomatch []string
	}{
		"star": {
			pat:     "*.tf",
			match:   []string{"main.tf", "a.tf"},
			nomatch: []string{"dir/main.tf", "main.tfvars"},
		},
		"doublestar": {
			pat:     "vendor/**",
			match:   []string{"vendor/a.tf", "vendor/a/b.tf"},
			nomatch: []string{"src/vendor/a.tf", "vendor"},
		},
		"question": {
			pat:     "main.t?",
			match:   []string{"main.tf"},
			nomatch: []string{"main.tfvars", "main.t"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			for _, s := range c.match {
				if !matchGlob(c.pat, s) {
					t.Errorf("matchGlob(%q, %q) = false, want true", c.pat, s)
				}
			}
			for _, s := range c.nomatch {
				if matchGlob(c.pat, s) {
					t.Errorf("matchGlob(%q, %q) = true, want false", c.pat, s)
				}
			}
		})
	}
}
