package cloudformation

import "testing"

// Item 6: coverage-guided fuzzing for the CFN parser. The invariant is
// no-panic + no hard error alongside resources (CFN reports problems as
// diagnostics, never as a hard error).
func FuzzItem6Parse(f *testing.F) {
	f.Add([]byte("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: x\n"))
	f.Add([]byte("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: &a [*a]\n"))
	f.Add([]byte("Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: !Join ['', ['a', !Ref B]]\n"))
	f.Add([]byte("\x00\x01\x02\xff\xfe"))
	f.Add([]byte(""))
	f.Add([]byte("{{{{[[[[}}}}]]]]"))
	f.Fuzz(func(t *testing.T, src []byte) {
		res, _, err := Adapter{}.Parse("fuzz.yaml", src)
		if err != nil && len(res) != 0 {
			t.Fatalf("hard error %q with %d resources", err, len(res))
		}
	})
}
