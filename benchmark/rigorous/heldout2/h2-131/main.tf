resource "aws_s3_bucket" "c131" {
  bucket = "clean-131"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c131" {
  bucket = aws_s3_bucket.c131.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c131.arn
    }
  }
}
resource "aws_kms_key" "c131" {
  description = "clean-131"
  enable_key_rotation = true
}
