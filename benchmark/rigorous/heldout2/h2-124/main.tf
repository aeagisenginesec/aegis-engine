resource "aws_s3_bucket" "c124" {
  bucket = "clean-124"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c124" {
  bucket = aws_s3_bucket.c124.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c124.arn
    }
  }
}
resource "aws_kms_key" "c124" {
  description = "clean-124"
  enable_key_rotation = true
}
