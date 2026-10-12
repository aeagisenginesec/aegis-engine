resource "aws_s3_bucket" "c48" {
  bucket = "clean-48"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c48" {
  bucket = aws_s3_bucket.c48.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c48.arn
    }
  }
}
resource "aws_kms_key" "c48" {
  description = "clean-48"
  enable_key_rotation = true
}
