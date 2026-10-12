resource "aws_s3_bucket" "c103" {
  bucket = "clean-103"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c103" {
  bucket = aws_s3_bucket.c103.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c103.arn
    }
  }
}
resource "aws_kms_key" "c103" {
  description = "clean-103"
  enable_key_rotation = true
}
