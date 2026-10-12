resource "aws_kms_key" "cmk" {
  description         = "cmk"
  enable_key_rotation = true
}

resource "aws_secretsmanager_secret" "vuln" {
  name       = "vuln"
  kms_key_id = aws_kms_key.cmk.arn
}

resource "aws_dynamodb_table" "vuln" {
  name         = "vuln"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.cmk.arn
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = true
}
