resource "aws_instance" "appserver" {
  ami           = "ami-0a1b2c3d4e5f60718"
  instance_type = "t3.micro"
  monitoring    = true
  metadata_options {
    http_tokens = "required"
  }
  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 30
    encrypted   = true
  }

  provisioner "remote-exec" {
    inline = ["sudo apt-get update -y"]

    connection {
      type     = "ssh"
      user     = "ubuntu"
      password = "fake-test-secret-001"
      host     = self.public_ip
    }
  }
}
