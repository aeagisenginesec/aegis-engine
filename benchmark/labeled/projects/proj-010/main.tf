resource "aws_ebs_volume" "vuln" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}
