package manifests

import "testing"

// Item 6: coverage-guided fuzzing for the manifests parser. Invariant:
// no panic; a hard error never accompanies resources.
func FuzzItem6Parse(f *testing.F) {
	f.Add([]byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"))
	f.Add([]byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n---\n: bad [\n"))
	f.Add([]byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  data: &a [*a]\n"))
	f.Add([]byte("\x00\x01\x02\xff\xfe"))
	f.Add([]byte(""))
	f.Add([]byte("---\n---\n---\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		res, _, err := Adapter{}.Parse("fuzz.yaml", src)
		if err != nil && len(res) != 0 {
			t.Fatalf("hard error %q with %d resources", err, len(res))
		}
	})
}
