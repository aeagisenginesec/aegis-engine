resource "aws_instance" "v63" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

resource "aws_cloudtrail" "v63" {
  name = "vuln-63"
  s3_bucket_name = aws_s3_bucket.v63.id
  enable_logging = false
}

resource "aws_s3_bucket" "v63" {
  bucket = "vuln-63-trail"
}

