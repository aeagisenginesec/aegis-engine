resource "aws_redshiftserverless_workgroup" "analytics" {
  namespace_name      = "analytics"
  workgroup_name      = "analytics"
  publicly_accessible = true
}
