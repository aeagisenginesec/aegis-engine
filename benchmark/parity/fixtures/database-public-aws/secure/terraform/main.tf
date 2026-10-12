resource "aws_db_instance" "db" {
  identifier          = "parity-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "Password123!"
  publicly_accessible = false
  storage_encrypted   = true
  skip_final_snapshot = false
}
