resource "aws_eks_node_group" "private" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-private-ng"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = var.private_subnet_ids
  instance_types  = ["m6i.large"]
  ami_type        = "AL2_x86_64"

  scaling_config {
    desired_size = 3
    min_size     = 2
    max_size     = 6
  }

  update_config {
    max_unavailable = 1
  }

  tags = {
    Name = "${var.cluster_name}-private-nodes"
  }
}
