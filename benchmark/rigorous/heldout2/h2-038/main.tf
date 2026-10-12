resource "aws_s3_bucket" "c38" {
  bucket = "clean-38"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c38" {
  bucket = aws_s3_bucket.c38.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c38.arn
    }
  }
}
resource "aws_kms_key" "c38" {
  description = "clean-38"
  enable_key_rotation = true
}
