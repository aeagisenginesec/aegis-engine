resource "aws_dynamodb_table" "api" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Project = var.project
  }
}

resource "aws_lambda_function" "api" {
  function_name = var.function_name
  role          = aws_iam_role.api.arn
  handler       = "main.handler"
  runtime       = "python3.12"
  filename      = "api.zip"
  timeout       = 30

  environment {
    variables = {
      DB_USER     = "api_svc"
      DB_PASSWORD = "ApiSvc2026!"
      TABLE_NAME  = aws_dynamodb_table.api.name
      AWS_REGION  = var.region
    }
  }

  tags = {
    Project = var.project
  }
}
