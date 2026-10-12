resource "aws_s3_bucket" "c39" {
  bucket = "clean-39"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c39" {
  bucket = aws_s3_bucket.c39.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c39.arn
    }
  }
}
resource "aws_kms_key" "c39" {
  description = "clean-39"
  enable_key_rotation = true
}
