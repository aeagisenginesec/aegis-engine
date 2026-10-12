terraform {
  backend "http" {
    address = "http://state.example.com/terraform"
  }
}

resource "aws_s3_bucket" "v104" {
  bucket = "vuln-104"
}

