resource "aws_s3_bucket" "demo" {
  bucket = "demo-no-pab-bucket"
  acl    = "private"
}
