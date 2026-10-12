

resource "aws_elasticache_replication_group" "sess" {
  replication_group_id       = "sess-redis"
  description                = "sess redis"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 1
  engine                     = "redis"
  engine_version             = "7.0"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = "PLACEHOLDER-ChangeMe-9xQ2vL7nR4t"
  snapshot_retention_limit   = 7
}


resource "aws_kms_key" "redis_sm" {
  description             = "Secrets Manager encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_secretsmanager_secret" "redis" {
  name       = "redis-secret"
  kms_key_id = aws_kms_key.redis_sm.arn
}
