resource "aws_eks_node_group" "worker" {
  cluster_name    = "prod"
  node_group_name = "worker"
  node_role_arn   = "arn:aws:iam::123456789012:role/eks-node"
  subnet_ids      = ["subnet-12345678"]
  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }
  remote_access {
    ec2_ssh_key = "prod-key"
  }
}
