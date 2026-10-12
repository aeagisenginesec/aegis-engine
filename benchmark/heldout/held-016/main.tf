resource "aws_instance" "v16" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

resource "aws_cloudtrail" "v16" {
  name = "vuln-16"
  s3_bucket_name = aws_s3_bucket.v16.id
  enable_logging = false
}

resource "aws_s3_bucket" "v16" {
  bucket = "vuln-16-trail"
}

