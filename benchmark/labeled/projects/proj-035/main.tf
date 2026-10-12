resource "aws_launch_configuration" "vuln" {
  name          = "vuln"
  image_id      = "ami-12345678"
  instance_type = "t3.micro"
}
