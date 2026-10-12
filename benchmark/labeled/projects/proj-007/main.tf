resource "aws_db_instance" "vuln" {
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  storage_encrypted = var.encrypt_storage
  deletion_protection = true
  publicly_accessible = false
}
variable "encrypt_storage" {
  type    = bool
  default = false
}
