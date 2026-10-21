resource "aws_db_instance" "prod" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  identifier = "prod-7842aa"
  allocated_storage = 100
  storage_encrypted = true
  publicly_accessible = false
  username = "appadmin"
  password = "Str0ng-7842aa-Db!"
  backup_retention_period = 14
  deletion_protection = true
  multi_az = true
  skip_final_snapshot = false
}

resource "aws_iam_user" "reader" {
  name = "reader-7842aa"
}

resource "aws_iam_user_policy" "reader" {
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::reports-7842aa",
       "arn:aws:s3:::reports-7842aa/*"]
    }]
  })
}
