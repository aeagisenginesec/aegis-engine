resource "aws_s3_bucket" "c14" {
  bucket = "clean-14"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c14" {
  bucket = aws_s3_bucket.c14.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c14.arn
    }
  }
}
resource "aws_kms_key" "c14" {
  description = "clean-14"
  enable_key_rotation = true
}
