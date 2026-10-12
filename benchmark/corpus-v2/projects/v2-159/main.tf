


resource "aws_iam_role" "worker_role" {
  name = "worker_role-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "worker" {
  function_name = "worker-fn"
  role          = aws_iam_role.worker_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  filename      = "worker.zip"
  tracing_config {
    mode = "Active"
  }
}


resource "aws_kms_key" "worker_q" {
  description             = "SQS queue encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_sqs_queue" "worker" {
  name              = "worker-queue"
  kms_master_key_id = aws_kms_key.worker_q.arn
}
