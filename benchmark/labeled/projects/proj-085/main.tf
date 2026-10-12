resource "aws_ssm_parameter" "vuln" {
  name  = "/prod/db/password"
  type  = "SecureString"
  value = "SuperSecret123!"
}
