resource "aws_s3_bucket" "c139" {
  bucket = "clean-139"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c139" {
  bucket = aws_s3_bucket.c139.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c139.arn
    }
  }
}
resource "aws_kms_key" "c139" {
  description = "clean-139"
  enable_key_rotation = true
}
