locals {
  db_password = "fake-test-secret-007"
  db_host     = "db.internal"
}

resource "aws_ssm_parameter" "db_host" {
  name  = "/prod/db/host"
  type  = "String"
  value = local.db_host
}
