terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

resource "aws_iam_role" "orders" {
  name = "orders-processor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "orders_scoped" {
  name = "orders-scoped"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.orders.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:us-west-2:123456789012:log-group:/aws/lambda/orders-processor:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "orders" {
  role       = aws_iam_role.orders.name
  policy_arn = aws_iam_policy.orders_scoped.arn
}

resource "aws_sqs_queue" "orders_dlq" {
  name = "orders-dlq"

  tags = {
    Name = "orders-dlq"
  }
}

resource "aws_dynamodb_table" "orders" {
  name         = "orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "order_id"

  attribute {
    name = "order_id"
    type = "S"
  }

  tags = {
    Name = "orders"
  }
}

resource "aws_cloudwatch_log_group" "orders" {
  name              = "/aws/lambda/orders-processor"
  retention_in_days = 30
}

resource "aws_lambda_function" "orders" {
  function_name                  = "orders-processor"
  role                           = aws_iam_role.orders.arn
  handler                        = "app.handler"
  runtime                        = "python3.12"
  filename                       = "orders.zip"
  reserved_concurrent_executions = 50

  dead_letter_config {
    target_arn = aws_sqs_queue.orders_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  vpc_config {
    subnet_ids         = ["subnet-priv1", "subnet-priv2"]
    security_group_ids = ["sg-lambda01"]
  }

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.orders.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.orders]

  tags = {
    Name = "orders-processor"
  }
}
