resource "aws_ssm_parameter" "vuln" {
  name  = "/prod/db/password"
  type  = "String"
  value = "SuperSecret123!"
}
