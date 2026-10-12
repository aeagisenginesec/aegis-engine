

resource "aws_iam_role" "wq" {
  name = "wq-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "wq" {
  name = "wq-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage"]
      Resource = ["arn:aws:sqs:us-east-1:123456789012:tasks"]
    }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "wq" {
  role       = aws_iam_role.wq.name
  policy_arn = aws_iam_policy.wq.arn
}
