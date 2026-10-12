resource "aws_eks_cluster" "vuln" {
  name     = "vuln"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  enabled_cluster_log_types = ["api", "audit", "authenticator"]
  encryption_config {
    provider {
      key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
    }
    resources = ["secrets"]
  }
  vpc_config {
    endpoint_public_access = true
  }
}
