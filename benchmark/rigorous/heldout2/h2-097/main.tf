resource "aws_s3_bucket" "c97" {
  bucket = "clean-97"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c97" {
  bucket = aws_s3_bucket.c97.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c97.arn
    }
  }
}
resource "aws_kms_key" "c97" {
  description = "clean-97"
  enable_key_rotation = true
}
