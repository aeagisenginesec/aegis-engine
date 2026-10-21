resource "aws_opensearch_domain" "logs" {
  domain_name = "logs-3e15f0"
  engine_version = "OpenSearch_2.11"
  cluster_config { instance_type = "t3.small.search" }
  encrypt_at_rest { enabled = false }
  node_to_node_encryption { enabled = false }
  domain_endpoint_options { enforce_https = false }
}
