

resource "aws_iam_role" "task" {
  name = "task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "task" {
  name = "task-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["arn:aws:logs:us-east-1:123456789012:log-group:/ecs/app:*"]
    }
    {
      Effect   = "Allow"
      Action   = ["ecr:BatchGetImage"]
      Resource = ["arn:aws:ecr:us-east-1:123456789012:repository/app"]
    }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "task" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.task.arn
}
