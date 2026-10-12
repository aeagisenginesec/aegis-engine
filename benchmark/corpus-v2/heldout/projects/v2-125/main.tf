resource "aws_instance" "bastion" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  monitoring                  = true
  metadata_options {
    http_tokens = "required"
  }
  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 30
    encrypted   = true
  }
}
