


resource "aws_kms_key" "db_sm" {
  description             = "Secrets Manager encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_secretsmanager_secret" "db" {
  name       = "db-secret"
  kms_key_id = aws_kms_key.db_sm.arn
}


resource "aws_kms_key" "api_sm" {
  description             = "Secrets Manager encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_secretsmanager_secret" "api" {
  name       = "api-secret"
  kms_key_id = aws_kms_key.api_sm.arn
}
