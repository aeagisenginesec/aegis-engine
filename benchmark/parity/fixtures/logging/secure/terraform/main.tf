resource "aws_s3_bucket" "data" {
  bucket = "parity-logged-data"
}

resource "aws_s3_bucket" "logs" {
  bucket = "parity-log-target"
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "log/"
}
