resource "aws_iam_role_policy" "deploy_admin" {
  name = "deploy-admin"
  role = "deployer"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}
