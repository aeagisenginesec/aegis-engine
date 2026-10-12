
locals {
  bucket_acl = "public-read"
}

resource "aws_s3_bucket" "site" {
}

resource "aws_s3_bucket_acl" "site" {
  bucket = aws_s3_bucket.site.id
  acl    = local.bucket_acl
}
