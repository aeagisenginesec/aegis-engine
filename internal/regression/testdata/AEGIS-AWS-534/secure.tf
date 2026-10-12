resource "aws_instance" "safe" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
  user_data     = "#!/bin/bash\necho hello"
  metadata_options {
    http_tokens = "required"
  }
}
