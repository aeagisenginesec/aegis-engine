package pulumi

import "testing"

// Item 6: coverage-guided fuzzing for the Pulumi parser. Invariant:
// no panic; a hard error never accompanies resources.
func FuzzItem6Parse(f *testing.F) {
	f.Add([]byte("name: t\nruntime: yaml\nresources:\n  b:\n    type: aws:s3:Bucket\n    properties:\n      bucket: x\n"))
	f.Add([]byte("name: t\nruntime: yaml\nvariables:\n  a: ${b}\n  b: ${a}\nresources:\n  b:\n    type: aws:s3:Bucket\n    properties:\n      bucket: ${a}\n"))
	f.Add([]byte("name: t\nruntime: yaml\nresources:\n  b:\n    type: aws:s3:Bucket\n    properties:\n      bucket: &a [*a]\n"))
	f.Add([]byte("\x00\x01\x02\xff\xfe"))
	f.Add([]byte(""))
	f.Add([]byte("${${${"))
	f.Fuzz(func(t *testing.T, src []byte) {
		res, _, err := Adapter{}.Parse("Pulumi.yaml", src)
		if err != nil && len(res) != 0 {
			t.Fatalf("hard error %q with %d resources", err, len(res))
		}
	})
}
