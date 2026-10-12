resource "aws_db_instance" "demo" {
  identifier          = "demo-secret-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "P7FAKESECRET-s3cr3t-v4lue-9z8x7w6v"
  skip_final_snapshot = true
}
