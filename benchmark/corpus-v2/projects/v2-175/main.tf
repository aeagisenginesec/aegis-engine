

resource "aws_iam_role" "bkp" {
  name = "bkp-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "bkp" {
  name = "bkp-least-priv"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
    {
      Effect   = "Allow"
      Action   = ["backup:StartBackupJob", "backup:DescribeBackupJob"]
      Resource = ["arn:aws:backup:us-east-1:123456789012:backup-vault:daily"]
    }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bkp" {
  role       = aws_iam_role.bkp.name
  policy_arn = aws_iam_policy.bkp.arn
}
