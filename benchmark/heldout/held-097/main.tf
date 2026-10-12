terraform {
  backend "http" {
    address = "http://state.example.com/terraform"
  }
}

resource "aws_s3_bucket" "v97" {
  bucket = "vuln-97"
}

