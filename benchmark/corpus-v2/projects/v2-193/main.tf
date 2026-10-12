


resource "aws_kms_key" "ev_t" {
  description             = "SNS topic encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_sns_topic" "ev" {
  name            = "ev-topic"
  kms_master_key_id = aws_kms_key.ev_t.arn
}


resource "aws_kms_key" "ev_q" {
  description             = "SQS queue encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_sqs_queue" "ev" {
  name              = "ev-queue"
  kms_master_key_id = aws_kms_key.ev_q.arn
}


resource "aws_iam_role" "ev_role" {
  name = "ev_role-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "ev" {
  function_name = "ev-fn"
  role          = aws_iam_role.ev_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  filename      = "ev.zip"
  tracing_config {
    mode = "Active"
  }
}
