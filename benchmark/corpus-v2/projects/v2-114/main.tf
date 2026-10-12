resource "aws_opensearch_domain" "search" {
  domain_name = "search"
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
  }
  cluster_config {
    instance_type            = "m6g.large.search"
    instance_count           = 2
    dedicated_master_enabled = true
    dedicated_master_type    = "m6g.large.search"
    dedicated_master_count   = 3
    zone_awareness_enabled   = true
  }
  log_publishing_options {
    cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:search-audit"
    log_type                 = "AUDIT_LOGS"
  }
  log_publishing_options {
    cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:search-slow"
    log_type                 = "SEARCH_SLOW_LOGS"
  }
  snapshot_options {
    automated_snapshot_start_hour = 3
  }
}
