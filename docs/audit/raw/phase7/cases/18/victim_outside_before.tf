resource "aws_s3_bucket" "demo" {
  bucket = "demo-no-versioning-bucket"
  acl    = "private"
}
