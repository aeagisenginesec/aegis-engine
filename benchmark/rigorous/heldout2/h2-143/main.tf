resource "aws_s3_bucket" "c143" {
  bucket = "clean-143"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c143" {
  bucket = aws_s3_bucket.c143.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c143.arn
    }
  }
}
resource "aws_kms_key" "c143" {
  description = "clean-143"
  enable_key_rotation = true
}
