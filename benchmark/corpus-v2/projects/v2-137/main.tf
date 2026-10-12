
resource "aws_ebs_volume" "data" {
  count             = 3
  availability_zone = "us-east-1a"
  size              = 50
  type              = "gp3"
}
