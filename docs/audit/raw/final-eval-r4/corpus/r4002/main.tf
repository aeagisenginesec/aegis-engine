resource "aws_eks_cluster" "main" {
  name = "main-5b5eb0"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster"
  vpc_config {
    subnet_ids = ["subnet-aaa", "subnet-bbb"]
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }
}
