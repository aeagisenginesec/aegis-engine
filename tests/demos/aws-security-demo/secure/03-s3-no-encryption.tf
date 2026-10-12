resource "aws_s3_bucket" "demo" {
  bucket = "demo-unencrypted-bucket"
  acl    = "private"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
