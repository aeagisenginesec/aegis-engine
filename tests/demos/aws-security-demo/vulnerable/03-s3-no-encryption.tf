resource "aws_s3_bucket" "demo" {
  bucket = "demo-unencrypted-bucket"
  acl    = "private"
}
