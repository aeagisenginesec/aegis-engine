resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id       = "sessions"
  description                = "sessions"
  engine                     = "redis"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 2
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  snapshot_retention_limit   = 7
  automatic_failover_enabled = true
}
