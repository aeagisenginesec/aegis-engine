resource "aws_s3_bucket" "c50" {
  bucket = "clean-50"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c50" {
  bucket = aws_s3_bucket.c50.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c50.arn
    }
  }
}
resource "aws_kms_key" "c50" {
  description = "clean-50"
  enable_key_rotation = true
}
