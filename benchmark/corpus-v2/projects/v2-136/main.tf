
data "aws_iam_policy_document" "vuln" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "vuln" {
  name               = "vuln-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "vuln" {
  name   = "vuln-inline"
  role   = aws_iam_role.vuln.id
  policy = data.aws_iam_policy_document.vuln.json
}
