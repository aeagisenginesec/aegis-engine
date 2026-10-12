resource "aws_s3_bucket" "c51" {
  bucket = "clean-51"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c51" {
  bucket = aws_s3_bucket.c51.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c51.arn
    }
  }
}
resource "aws_kms_key" "c51" {
  description = "clean-51"
  enable_key_rotation = true
}
