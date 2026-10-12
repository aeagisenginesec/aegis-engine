resource "aws_s3_bucket" "c72" {
  bucket = "clean-72"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c72" {
  bucket = aws_s3_bucket.c72.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c72.arn
    }
  }
}
resource "aws_kms_key" "c72" {
  description = "clean-72"
  enable_key_rotation = true
}
