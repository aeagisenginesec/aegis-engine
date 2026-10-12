resource "aws_elasticache_user" "vuln" {
  user_id       = "vuln"
  user_name     = "vuln"
  engine        = "REDIS"
  access_string = "on ~* &* +@all"
  passwords     = ["TempPassword123!"]
}
