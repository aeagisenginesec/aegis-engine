package bicep

import "testing"

// Item 6: coverage-guided fuzzing for the Bicep parser. Invariant: no
// panic; a hard error never accompanies resources.
func FuzzItem6Parse(f *testing.F) {
	f.Add([]byte("param location string = 'eastus'\nresource st 'Microsoft.Storage/storageAccounts@2023-01-01' = { name: 'x' location: location }\n"))
	f.Add([]byte("var a = b\nvar b = a\n"))
	f.Add([]byte("var x = [[[[[[[[[[\n"))
	f.Add([]byte("var x = true ? true ? true ? 1 : 2 : 3 : 4\n"))
	f.Add([]byte("\x00\x01\x02\xff\xfe"))
	f.Add([]byte(""))
	f.Add([]byte("''''''''''"))
	f.Fuzz(func(t *testing.T, src []byte) {
		res, _, err := Adapter{}.Parse("fuzz.bicep", src)
		if err != nil && len(res) != 0 {
			t.Fatalf("hard error %q with %d resources", err, len(res))
		}
	})
}
