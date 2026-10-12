resource "aws_kms_key" "ledger" {
  description         = "ledger"
  enable_key_rotation = true
  policy              = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
POLICY
}
