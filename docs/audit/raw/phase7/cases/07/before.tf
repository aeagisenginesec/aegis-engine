resource "aws_ebs_volume" "demo" {
  availability_zone = "us-east-1a"
  size              = 40
}
