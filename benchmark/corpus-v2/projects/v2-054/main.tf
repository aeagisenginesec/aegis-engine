resource "aws_eks_node_group" "general" {
  cluster_name    = "prod"
  node_group_name = "general"
  node_role_arn   = "arn:aws:iam::123456789012:role/eks-nodes"
  subnet_ids      = ["subnet-0a1b2c3d"]

  scaling_config {
    desired_size = 2
    max_size     = 4
    min_size     = 1
  }

  remote_access {
    ec2_ssh_key               = "prod-key"
    source_security_group_ids = ["sg-0a1b2c3d"]
  }
}
