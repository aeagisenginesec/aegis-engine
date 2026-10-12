resource "aws_s3_bucket" "c73" {
  bucket = "clean-73"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c73" {
  bucket = aws_s3_bucket.c73.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c73.arn
    }
  }
}
resource "aws_kms_key" "c73" {
  description = "clean-73"
  enable_key_rotation = true
}
