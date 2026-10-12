resource "aws_sagemaker_notebook_instance" "studio" {
  name          = "studio"
  role_arn      = "arn:aws:iam::123456789012:role/sagemaker"
  instance_type = "ml.t3.medium"
  kms_key_id    = "arn:aws:kms:us-east-1:123456789012:key/abc"
  direct_internet_access = "Disabled"
  instance_metadata_service_configuration {
    minimum_instance_metadata_service_version = 2
  }
}
