


resource "aws_iam_role" "img_role" {
  name = "img_role-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "img" {
  function_name = "img-fn"
  role          = aws_iam_role.img_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  filename      = "img.zip"
  tracing_config {
    mode = "Active"
  }
}


resource "aws_kms_key" "img_ecr" {
  description             = "ECR repository encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_ecr_repository" "img" {
  name                 = "img-repo"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.img_ecr.arn
  }
}
