resource "aws_efs_file_system" "vuln" {
  encrypted  = true
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}

resource "aws_efs_file_system_policy" "p" {
  file_system_id = aws_efs_file_system.vuln.id
  policy         = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["elasticfilesystem:ClientMount"],
      "Resource": "*",
      "Condition": {"Bool": {"aws:SecureTransport": "true"}}
    }
  ]
}
POLICY
}
