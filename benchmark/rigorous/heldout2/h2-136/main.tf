resource "aws_s3_bucket" "c136" {
  bucket = "clean-136"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c136" {
  bucket = aws_s3_bucket.c136.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c136.arn
    }
  }
}
resource "aws_kms_key" "c136" {
  description = "clean-136"
  enable_key_rotation = true
}
