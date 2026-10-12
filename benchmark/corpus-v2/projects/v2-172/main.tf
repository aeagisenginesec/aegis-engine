

resource "aws_iam_role" "ldd" {
  name = "ldd-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "ldd" {
  statement {
    effect = "Allow"
    actions = [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:Query"
    ]
    resources = [
    "arn:aws:dynamodb:us-east-1:123456789012:table/app"
    ]
  }
}
resource "aws_iam_policy" "ldd_pol" {
  name   = "ldd-least-priv"
  policy = data.aws_iam_policy_document.ldd.json
}

resource "aws_iam_role_policy_attachment" "ldd" {
  role       = aws_iam_role.ldd.name
  policy_arn = aws_iam_policy.ldd_pol.arn
}
