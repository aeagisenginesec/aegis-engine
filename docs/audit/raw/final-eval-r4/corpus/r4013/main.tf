resource "aws_db_instance" "prod" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  identifier = "prod-fc05da"
  allocated_storage = 100
  storage_encrypted = true
  publicly_accessible = false
  username = "appadmin"
  password = "Str0ng-fc05da-Db!"
  backup_retention_period = 14
  deletion_protection = true
  multi_az = true
  skip_final_snapshot = false
}

resource "aws_instance" "web" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
    http_endpoint = "enabled"
  }
  tags = { Name = "web-fc05da" }
}
