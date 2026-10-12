resource "aws_neptune_cluster" "graph" {
  cluster_identifier             = "graph"
  engine                         = "neptune"
  backup_retention_period              = 7
  deletion_protection                  = true
  iam_database_authentication_enabled  = true
  enable_cloudwatch_logs_exports       = ["audit"]
}
