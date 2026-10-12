resource "aws_db_instance" "demo" {
  identifier           = "demo-public-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "placeholder-not-a-real-secret"
  publicly_accessible  = true
  skip_final_snapshot  = true
}
