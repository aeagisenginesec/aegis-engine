resource "aws_iam_user" "reader" {
  name = "reader-82a3a7"
}

resource "aws_iam_user_policy" "reader" {
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::reports-82a3a7",
       "arn:aws:s3:::reports-82a3a7/*"]
    }]
  })
}

resource "aws_s3_bucket" "logs" {
  bucket = "app-logs-82a3a7"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
