terraform {
  backend "http" {
    address = "http://state.example.com/terraform"
  }
}

resource "aws_s3_bucket" "v103" {
  bucket = "vuln-103"
}

