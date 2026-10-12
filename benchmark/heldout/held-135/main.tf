resource "aws_s3_bucket" "v135" {
  bucket = "vuln-135-data"
}

resource "aws_s3_bucket_acl" "v135" {
  bucket = aws_s3_bucket.v135.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v135" {
  bucket = aws_s3_bucket.v135.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-135-data/*" }]
  })
}

resource "aws_instance" "v135" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}

