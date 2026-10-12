resource "aws_s3_bucket" "c11" {
  bucket = "clean-11"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c11" {
  bucket = aws_s3_bucket.c11.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c11.arn
    }
  }
}
resource "aws_kms_key" "c11" {
  description = "clean-11"
  enable_key_rotation = true
}
