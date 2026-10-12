resource "aws_eks_cluster" "prod" {
  name     = "prod"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  encryption_config {
    provider {
      key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
    }
    resources = ["secrets"]
  }
  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}
