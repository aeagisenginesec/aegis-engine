package planjson

import "testing"

// Item 6: coverage-guided fuzzing for the plan-JSON parser. Invariant:
// no panic; a hard error never accompanies resources.
func FuzzItem6Parse(f *testing.F) {
	f.Add([]byte(`{"format_version":"1.0","planned_values":{"root_module":{"resources":[]}}}`))
	f.Add([]byte(`{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b","values":{"bucket":"x"}}]}}}`))
	f.Add([]byte(`{"a":[[[[[[[[[[`))
	f.Add([]byte("\x00\x01\x02\xff\xfe"))
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, src []byte) {
		res, _, err := Adapter{}.Parse("fuzz.plan.json", src)
		if err != nil && len(res) != 0 {
			t.Fatalf("hard error %q with %d resources", err, len(res))
		}
	})
}
