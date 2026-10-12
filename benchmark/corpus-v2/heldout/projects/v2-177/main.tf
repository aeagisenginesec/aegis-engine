

resource "aws_iam_role" "pipe" {
  name = "pipe-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "pipe" {
  statement {
    effect = "Allow"
    actions = [
    "s3:GetObject",
    "s3:PutObject"
    ]
    resources = [
    "arn:aws:s3:::pipe-bucket/*"
    ]
  }
}
resource "aws_iam_policy" "pipe_pol" {
  name   = "pipe-least-priv"
  policy = data.aws_iam_policy_document.pipe.json
}

resource "aws_iam_role_policy_attachment" "pipe" {
  role       = aws_iam_role.pipe.name
  policy_arn = aws_iam_policy.pipe_pol.arn
}
