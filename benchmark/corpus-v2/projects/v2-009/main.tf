resource "aws_iam_user" "svc_deploy" {
  name = "svc-deploy"
}

resource "aws_iam_access_key" "svc_deploy" {
  user = aws_iam_user.svc_deploy.name
}
