resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier  = "warehouse"
  node_type           = "dc2.large"
  master_username     = "admin"
  encrypted           = true
  publicly_accessible = false
  enhanced_vpc_routing = true
  logging {
    bucket_name = "redshift-logs-bucket"
  }
}
