resource "aws_s3_bucket" "c119" {
  bucket = "clean-119"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c119" {
  bucket = aws_s3_bucket.c119.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c119.arn
    }
  }
}
resource "aws_kms_key" "c119" {
  description = "clean-119"
  enable_key_rotation = true
}
