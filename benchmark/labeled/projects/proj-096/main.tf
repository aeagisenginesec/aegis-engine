resource "aws_ebs_volume" "vuln" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
