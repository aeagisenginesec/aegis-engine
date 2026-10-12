resource "aws_opensearch_domain" "vuln" {
  domain_name = "vuln"
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
    instance_count           = 3
    dedicated_master_enabled = true
    zone_awareness_enabled   = true
  }
  vpc_options {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
