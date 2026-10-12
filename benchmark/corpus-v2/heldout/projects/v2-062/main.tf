resource "aws_emr_security_configuration" "warehouse" {
  name = "warehouse-sec"
  configuration = <<JSON
{
  "EncryptionConfiguration": {
    "EnableInTransitEncryption": true,
    "EnableAtRestEncryption": false
  }
}
JSON
}
