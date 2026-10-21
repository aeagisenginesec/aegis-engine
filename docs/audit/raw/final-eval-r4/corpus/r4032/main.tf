resource "aws_db_instance" "prod" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  identifier = "prod-67de90"
  allocated_storage = 100
  storage_encrypted = true
  publicly_accessible = false
  username = "appadmin"
  password = "Str0ng-67de90-Db!"
  backup_retention_period = 14
  deletion_protection = true
  multi_az = true
  skip_final_snapshot = false
}

resource "aws_iam_user" "ops" {
  name = "ops-67de90"
}

resource "aws_iam_user_policy_attachment" "ops" {
  user = aws_iam_user.ops.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
