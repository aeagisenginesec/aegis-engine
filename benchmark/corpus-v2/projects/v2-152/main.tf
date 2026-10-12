

resource "aws_elasticache_replication_group" "cache" {
  replication_group_id       = "cache-redis"
  description                = "cache redis"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 1
  engine                     = "redis"
  engine_version             = "7.0"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = "PLACEHOLDER-ChangeMe-9xQ2vL7nR4t"
  snapshot_retention_limit   = 7
}
