resource "aws_s3_bucket" "c140" {
  bucket = "clean-140"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c140" {
  bucket = aws_s3_bucket.c140.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c140.arn
    }
  }
}
resource "aws_kms_key" "c140" {
  description = "clean-140"
  enable_key_rotation = true
}
