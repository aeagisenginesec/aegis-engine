resource "aws_elasticache_replication_group" "cache" {
  replication_group_id = "cache-98a983"
  node_type = "cache.t3.micro"
  num_cache_clusters = 1
  transit_encryption_enabled = false
  at_rest_encryption_enabled = false
}

resource "aws_iam_user" "reader" {
  name = "reader-98a983"
}

resource "aws_iam_user_policy" "reader" {
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::reports-98a983",
       "arn:aws:s3:::reports-98a983/*"]
    }]
  })
}
