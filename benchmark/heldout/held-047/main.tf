resource "aws_ebs_volume" "v47" {
  availability_zone = "us-east-1a"
  size = 40
}

terraform {
  backend "http" {
    address = "http://state.example.com/terraform"
  }
}

resource "aws_s3_bucket" "v47" {
  bucket = "vuln-47"
}

