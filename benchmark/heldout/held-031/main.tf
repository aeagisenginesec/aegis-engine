resource "aws_cloudtrail" "v31" {
  name = "vuln-31"
  s3_bucket_name = aws_s3_bucket.v31.id
  enable_logging = false
}

resource "aws_s3_bucket" "v31" {
  bucket = "vuln-31-trail"
}

resource "aws_instance" "v31" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

