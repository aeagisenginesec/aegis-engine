resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
  user_data     = "DB_PASSWORD=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  metadata_options {
    http_tokens = "required"
  }
}
