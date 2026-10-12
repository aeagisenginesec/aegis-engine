resource "aws_elasticache_replication_group" "vuln" {
  replication_group_id       = "vuln"
  description                = "vuln"
  transit_encryption_enabled = true
  auth_token                 = "TempAuthToken123456!"
  at_rest_encryption_enabled = true
  snapshot_retention_limit   = 7
}
