resource "aws_s3_bucket" "c66" {
  bucket = "clean-66"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c66" {
  bucket = aws_s3_bucket.c66.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c66.arn
    }
  }
}
resource "aws_kms_key" "c66" {
  description = "clean-66"
  enable_key_rotation = true
}
