resource "aws_iam_role" "report_fn" {
  name = "report-fn"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "report_all" {
  name = "report-all"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "report_attach" {
  role       = aws_iam_role.report_fn.name
  policy_arn = aws_iam_policy.report_all.arn
}

resource "aws_lambda_function" "report" {
  function_name = "report"
  role          = aws_iam_role.report_fn.arn
  runtime       = "python3.13"
  handler       = "index.handler"
  tracing_config {
    mode = "Active"
  }
  vpc_config {
    subnet_ids         = ["subnet-0a1b2c3d"]
    security_group_ids = ["sg-0a1b2c3d"]
  }
  reserved_concurrent_executions = 10
  code_signing_config {
  }
  dead_letter_config {
    target_arn = "arn:aws:sqs:us-east-1:123456789012:dlq"
  }
}
