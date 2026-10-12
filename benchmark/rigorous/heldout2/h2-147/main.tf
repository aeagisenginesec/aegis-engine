resource "aws_s3_bucket" "c147" {
  bucket = "clean-147"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c147" {
  bucket = aws_s3_bucket.c147.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c147.arn
    }
  }
}
resource "aws_kms_key" "c147" {
  description = "clean-147"
  enable_key_rotation = true
}
