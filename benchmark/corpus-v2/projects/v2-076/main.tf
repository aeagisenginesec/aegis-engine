resource "aws_db_proxy" "ledger" {
  name                   = "ledger"
  engine_family          = "POSTGRESQL"
  role_arn               = "arn:aws:iam::123456789012:role/db-proxy"
  vpc_subnet_ids         = ["subnet-12345678"]
  vpc_security_group_ids = ["sg-12345678"]
  auth {
    auth_scheme = "SECRETS"
    iam_auth    = "REQUIRED"
    secret_arn  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds"
  }
  require_tls = false
}
