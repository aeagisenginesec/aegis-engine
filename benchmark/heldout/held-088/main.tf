resource "aws_instance" "v88" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

resource "aws_cloudtrail" "v88" {
  name = "vuln-88"
  s3_bucket_name = aws_s3_bucket.v88.id
  enable_logging = false
}

resource "aws_s3_bucket" "v88" {
  bucket = "vuln-88-trail"
}

