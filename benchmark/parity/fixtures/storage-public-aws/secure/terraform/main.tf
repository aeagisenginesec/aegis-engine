resource "aws_s3_bucket" "data" {
  bucket = "parity-public-data"
  acl    = "private"
}
