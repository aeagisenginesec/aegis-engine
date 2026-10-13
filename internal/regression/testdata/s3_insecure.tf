# Data-lake bucket: public ACL, no default encryption, versioning suspended,
# no access logging. The public ACL (002), versioning (012), exfiltration
# path (104), and hardening findings fire. SSE (001) and PAB (206) do NOT
# fire: the bucket is intentionally public, so recommending encryption
# at rest or a public access block is wrong advice (see
# bucketIntentionallyPublic).
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
