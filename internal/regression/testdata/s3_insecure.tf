# Data-lake bucket: public ACL, no default encryption, versioning suspended,
# no access logging. Each of these should be a finding.
resource "aws_s3_bucket" "data_lake" {
  bucket = "acme-data-lake-prod"
  acl    = "public-read"

  tags = {
    Environment = "prod"
    Owner       = "data-team"
  }
}

resource "aws_s3_bucket_versioning" "data_lake" {
  bucket = "acme-data-lake-prod"

  versioning_configuration {
    status = "Suspended"
  }
}
