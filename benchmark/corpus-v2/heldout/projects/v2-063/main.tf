resource "aws_dax_cluster" "cache" {
  cluster_name       = "cache"
  iam_role_arn       = "arn:aws:iam::123456789012:role/dax"
  node_type          = "dax.r5.large"
  replication_factor = 2
  server_side_encryption {
    enabled = true
  }
}
