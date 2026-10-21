resource "aws_s3_bucket" "logs" {
  bucket = "app-logs-0918cb"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

variable "db_password" {
  type = string
  default = "Sup3rSecret!-prod-2024"
  description = "Database master password"
}

resource "aws_db_instance" "app" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  identifier = "app-0918cb"
  allocated_storage = 20
  storage_encrypted = true
  username = "appadmin"
  password = var.db_password
  skip_final_snapshot = true
}

resource "aws_db_instance" "prod" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  identifier = "prod-0918cb"
  allocated_storage = 100
  storage_encrypted = true
  publicly_accessible = false
  username = "appadmin"
  password = "Str0ng-0918cb-Db!"
  backup_retention_period = 14
  deletion_protection = true
  multi_az = true
  skip_final_snapshot = false
}
