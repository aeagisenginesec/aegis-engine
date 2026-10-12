resource "aws_iam_policy" "safe" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::app-data/*"]}]
}
POLICY
}
