resource "aws_emr_security_configuration" "analytics" {
  name = "analytics-sec"
  configuration = <<JSON
{
  "EncryptionConfiguration": {
    "EnableInTransitEncryption": false,
    "EnableAtRestEncryption": true
  }
}
JSON
}
