resource "aws_docdb_cluster" "ledger" {
  cluster_identifier              = "ledger"
  engine                          = "docdb"
  master_username                 = "admin"
  backup_retention_period         = 7
  deletion_protection             = true
  enabled_cloudwatch_logs_exports = ["audit", "profiler"]
}
