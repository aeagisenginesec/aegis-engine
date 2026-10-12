resource "aws_cloudtrail" "v92" {
  name = "vuln-92"
  s3_bucket_name = aws_s3_bucket.v92.id
  enable_logging = false
}

resource "aws_s3_bucket" "v92" {
  bucket = "vuln-92-trail"
}

resource "aws_instance" "v92" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

