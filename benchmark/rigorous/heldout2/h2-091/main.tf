resource "aws_s3_bucket" "c91" {
  bucket = "clean-91"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c91" {
  bucket = aws_s3_bucket.c91.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c91.arn
    }
  }
}
resource "aws_kms_key" "c91" {
  description = "clean-91"
  enable_key_rotation = true
}
