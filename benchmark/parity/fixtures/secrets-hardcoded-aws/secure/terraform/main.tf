data "aws_secretsmanager_secret_version" "db" {
  secret_id = "parity-db-password"
}

resource "aws_db_instance" "db" {
  identifier          = "parity-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = data.aws_secretsmanager_secret_version.db.secret_string
  publicly_accessible = false
  skip_final_snapshot = true
}
