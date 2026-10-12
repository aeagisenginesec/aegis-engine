resource "aws_instance" "dbproxy" {
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

  provisioner "file" {
    source      = "proxy.conf"
    destination = "/etc/proxy/proxy.conf"

    connection {
      type     = "ssh"
      user     = "admin"
      password = "fake-test-secret-006"
      host     = self.private_ip
    }
  }
}
