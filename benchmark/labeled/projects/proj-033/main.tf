resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
}
