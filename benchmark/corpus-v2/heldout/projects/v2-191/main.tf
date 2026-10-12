

resource "aws_s3_bucket" "raw" {
}

resource "aws_s3_bucket_versioning" "raw_v" {
  bucket = aws_s3_bucket.raw.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "raw_sse" {
  bucket = aws_s3_bucket.raw.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_public_access_block" "raw_pab" {
  bucket                  = aws_s3_bucket.raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_logging" "raw_log" {
  bucket        = aws_s3_bucket.raw.id
  target_bucket = aws_s3_bucket.raw_logs.id
  target_prefix = "raw/"
}
resource "aws_s3_bucket_lifecycle_configuration" "raw_lc" {
  bucket = aws_s3_bucket.raw.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket" "raw_logs" {
}
resource "aws_s3_bucket_versioning" "raw_logs_v" {
  bucket = aws_s3_bucket.raw_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "raw_logs_sse" {
  bucket = aws_s3_bucket.raw_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "raw_logs_pab" {
  bucket                  = aws_s3_bucket.raw_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "raw_tls" {
  bucket = aws_s3_bucket.raw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.raw.arn, "${aws_s3_bucket.raw.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}


resource "aws_iam_role" "etl_role" {
  name = "etl_role-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "etl" {
  function_name = "etl-fn"
  role          = aws_iam_role.etl_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  filename      = "etl.zip"
  tracing_config {
    mode = "Active"
  }
}

resource "aws_dynamodb_table" "etl" {
  name         = "etl-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  server_side_encryption {
    enabled = true
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = true
}
