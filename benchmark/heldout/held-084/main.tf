resource "aws_dynamodb_table" "v84" {
  name = "vuln-84"
  hash_key = "id"
  billing_mode = "PAY_PER_REQUEST"
  attribute { name = "id" type = "S" }
}

resource "aws_iam_policy" "v84" {
  name = "vuln-84"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = "dynamodb:*" Resource = "*" }]
  })
}

