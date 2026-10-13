package arm

import "testing"

// Item 6: coverage-guided fuzzing for the ARM parser. Invariant: no
// panic; a hard error never accompanies resources.
func FuzzItem6Parse(f *testing.F) {
	f.Add([]byte(`{"$schema":"x/deploymentTemplate.json#","contentVersion":"1.0.0.0","resources":[]}`))
	f.Add([]byte(`{"$schema":"x/deploymentTemplate.json#","variables":{"a":"[variables('b')]","b":"[variables('a')]"},"resources":[{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"[variables('a')]"}]}`))
	f.Add([]byte(`{"$schema":"x/deploymentTemplate.json#","variables":{"v":"[concat(concat(concat('a')))]"},"resources":[]}`))
	f.Add([]byte("\x00\x01\x02\xff\xfe"))
	f.Add([]byte(""))
	f.Add([]byte("[[[[[[[[[["))
	f.Fuzz(func(t *testing.T, src []byte) {
		res, _, err := Adapter{}.Parse("fuzz.json", src)
		if err != nil && len(res) != 0 {
			t.Fatalf("hard error %q with %d resources", err, len(res))
		}
	})
}
