resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
}
POLICY
}
