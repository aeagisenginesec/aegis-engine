resource "aws_db_instance" "v9" {
  identifier = "vuln-9"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
}

