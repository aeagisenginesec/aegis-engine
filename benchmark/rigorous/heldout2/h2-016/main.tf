resource "aws_s3_bucket" "c16" {
  bucket = "clean-16"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c16" {
  bucket = aws_s3_bucket.c16.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c16.arn
    }
  }
}
resource "aws_kms_key" "c16" {
  description = "clean-16"
  enable_key_rotation = true
}
