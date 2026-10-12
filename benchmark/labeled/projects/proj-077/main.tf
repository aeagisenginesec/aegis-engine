resource "aws_sns_topic" "vuln" {
  name              = "vuln"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "p" {
  arn    = aws_sns_topic.vuln.arn
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "sns:Publish",
      "Resource": "*"
    }
  ]
}
POLICY
}
