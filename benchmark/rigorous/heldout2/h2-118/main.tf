resource "aws_s3_bucket" "c118" {
  bucket = "clean-118"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "c118" {
  bucket = aws_s3_bucket.c118.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.c118.arn
    }
  }
}
resource "aws_kms_key" "c118" {
  description = "clean-118"
  enable_key_rotation = true
}
