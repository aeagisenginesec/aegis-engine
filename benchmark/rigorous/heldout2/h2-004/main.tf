resource "aws_s3_bucket" "c4" {
  bucket = "clean-4"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c4" {
  bucket = aws_s3_bucket.c4.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c4.arn
    }
  }
}
resource "aws_kms_key" "c4" {
  description = "clean-4"
  enable_key_rotation = true
}
