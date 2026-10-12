resource "aws_eks_cluster" "vuln" {
  name     = "vuln"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  enabled_cluster_log_types = ["api", "audit", "authenticator"]
}
