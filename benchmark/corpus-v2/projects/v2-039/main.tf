resource "aws_secretsmanager_secret" "svc" {
  name       = "svc"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
}

resource "aws_secretsmanager_secret_rotation" "svc" {
  secret_id           = aws_secretsmanager_secret.svc.id
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:123456789012:function:rotator"

  rotation_rules {
    automatically_after_days = 180
  }
}
