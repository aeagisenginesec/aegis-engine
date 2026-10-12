resource "aws_db_instance" "v74" {
  identifier = "vuln-74"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
}

