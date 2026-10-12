resource "aws_s3_bucket" "demo" {
  bucket = "demo-public-acl-bucket"
  acl    = "public-read"
}
