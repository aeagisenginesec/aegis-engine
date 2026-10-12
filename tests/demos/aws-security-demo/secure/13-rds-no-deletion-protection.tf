resource "aws_db_instance" "demo" {
  identifier          = "demo-no-del-protection"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "placeholder-not-a-real-secret"
  deletion_protection = true
  skip_final_snapshot = true
}
