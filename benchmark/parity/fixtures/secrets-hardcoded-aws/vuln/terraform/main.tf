resource "aws_db_instance" "db" {
  identifier          = "parity-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "Hardcoded123!"
  publicly_accessible = false
  skip_final_snapshot = true
}
