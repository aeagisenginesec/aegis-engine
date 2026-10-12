# Aegis Engine demo: a small app with 4 deliberate misconfigurations.
# Run: ./aegis scan demo/vulnerable

variable "environment" {
  default = "dev"
}

resource "aws_s3_bucket" "uploads" {
  bucket = "demo-uploads-${var.environment}"
  # NOTE: no encryption, no versioning
}

resource "aws_security_group" "app" {
  name = "demo-app"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # world-open
  }
}

resource "aws_db_instance" "app" {
  identifier          = "demo-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  storage_encrypted   = false
  deletion_protection = false
}
