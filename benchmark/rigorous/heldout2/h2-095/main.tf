resource "aws_s3_bucket" "c95" {
  bucket = "clean-95"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c95" {
  bucket = aws_s3_bucket.c95.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c95.arn
    }
  }
}
resource "aws_kms_key" "c95" {
  description = "clean-95"
  enable_key_rotation = true
}
