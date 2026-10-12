resource "aws_ssm_parameter" "demo" {
  name  = "/demo/db-password"
  type  = "SecureString"
  value = "placeholder-not-a-real-secret"
}
