resource "aws_secretsmanager_secret" "demo" {
  name = "demo-secret"
}
resource "aws_secretsmanager_secret_rotation" "demo" {
  secret_id           = aws_secretsmanager_secret.demo.id
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:123456789012:function:demo-rotation"
  rotation_rules {
    automatically_after_days = 30
  }
}
