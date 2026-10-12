resource "aws_elasticache_replication_group" "session" {
  replication_group_id       = "session"
  description                = "session"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 2
  transit_encryption_enabled   = true
  at_rest_encryption_enabled   = true
  snapshot_retention_limit     = 7
  automatic_failover_enabled   = true
}
