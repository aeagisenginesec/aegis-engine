resource "aws_instance" "demo" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
}
