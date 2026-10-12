resource "aws_redshift_cluster" "vuln" {
  cluster_identifier   = "vuln"
  node_type            = "dc2.large"
  master_username      = "admin"
  encrypted            = true
  publicly_accessible  = true
  cluster_subnet_group_name = "vuln-subnet-group"
  logging {
    bucket_name = "redshift-logs-bucket"
  }
}
