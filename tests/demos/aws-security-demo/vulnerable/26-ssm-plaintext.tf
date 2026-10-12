resource "aws_ssm_parameter" "demo" {
  name  = "/demo/db-password"
  type  = "String"
  value = "placeholder-not-a-real-secret"
}
