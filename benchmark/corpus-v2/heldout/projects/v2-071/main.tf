resource "aws_launch_template" "worker" {
  name          = "worker"
  image_id      = "ami-12345678"
  instance_type = "t3.micro"
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = 30
      encrypted   = false
    }
  }
  metadata_options {
    http_tokens = "required"
  }
}
