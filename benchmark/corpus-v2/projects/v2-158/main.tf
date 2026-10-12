


resource "aws_iam_role" "notifier_role" {
  name = "notifier_role-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "notifier" {
  function_name = "notifier-fn"
  role          = aws_iam_role.notifier_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  filename      = "notifier.zip"
  tracing_config {
    mode = "Active"
  }
}

resource "aws_sns_topic" "notifier" {
  name              = "notifier-topic"
  kms_master_key_id = "alias/aws/sns"
}
