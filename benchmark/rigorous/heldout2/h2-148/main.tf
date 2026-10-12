resource "aws_s3_bucket" "c148" {
  bucket = "clean-148"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c148" {
  bucket = aws_s3_bucket.c148.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c148.arn
    }
  }
}
resource "aws_kms_key" "c148" {
  description = "clean-148"
  enable_key_rotation = true
}
