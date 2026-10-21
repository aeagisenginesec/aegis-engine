resource "aws_db_instance" "ephemeral" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  identifier = "ephemeral-ccf569"
  allocated_storage = 20
  storage_encrypted = true
  publicly_accessible = false
  username = "appadmin"
  password = "Str0ng-ccf569-Db!"
  backup_retention_period = 0
  skip_final_snapshot = true
}

resource "aws_iam_user" "deployer" {
  name = "deployer-ccf569"
}

resource "aws_iam_user_policy" "deployer" {
  user = aws_iam_user.deployer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "*"
      Resource = "*"
    }]
  })
}
