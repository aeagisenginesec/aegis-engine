resource "aws_sagemaker_notebook_instance" "research" {
  name               = "research"
  instance_type      = "ml.t3.medium"
  role_arn           = "arn:aws:iam::123456789012:role/sagemaker"
  subnet_id          = "subnet-0a1b2c3d"
  security_groups    = ["sg-0a1b2c3d"]
  kms_key_id         = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
  direct_internet_access = "Enabled"

  instance_metadata_service_configuration {
    minimum_instance_metadata_service_version = 2
  }
}
