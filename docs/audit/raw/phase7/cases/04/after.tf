resource "aws_db_instance" "demo" {
  identifier          = "demo-unencrypted-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "placeholder-not-a-real-secret"
  skip_final_snapshot = true
  storage_encrypted = true
}
