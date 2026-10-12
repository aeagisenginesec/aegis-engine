resource "aws_s3_bucket" "c135" {
  bucket = "clean-135"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c135" {
  bucket = aws_s3_bucket.c135.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c135.arn
    }
  }
}
resource "aws_kms_key" "c135" {
  description = "clean-135"
  enable_key_rotation = true
}
