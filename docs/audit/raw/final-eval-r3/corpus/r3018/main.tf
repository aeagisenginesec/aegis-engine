resource "aws_iam_user" "deployer" {
  name = "deployer-e4958c"
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

resource "aws_db_instance" "dev" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  identifier = "dev-e4958c"
  allocated_storage = 20
  storage_encrypted = true
  publicly_accessible = false
  username = "postgres"
  password = "password123"
  backup_retention_period = 7
  skip_final_snapshot = true
}
