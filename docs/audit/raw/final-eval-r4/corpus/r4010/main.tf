resource "aws_iam_role" "partner" {
  name = "partner-6be542"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = "*" }
      Action = "sts:AssumeRole"
    }]
  })
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
  identifier = "app-6be542"
  allocated_storage = 20
  storage_encrypted = true
  username = "appadmin"
  password = var.db_password
  skip_final_snapshot = true
}
