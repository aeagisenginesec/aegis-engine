resource "aws_memorydb_cluster" "session" {
  cluster_name             = "session"
  node_type                = "db.r6g.large"
  acl_name                 = "open-access"
  tls_enabled              = false
  snapshot_retention_limit = 7
}
