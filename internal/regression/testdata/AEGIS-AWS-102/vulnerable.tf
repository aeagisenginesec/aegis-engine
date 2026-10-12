resource "aws_iam_policy" "vuln" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]
}
POLICY
}
