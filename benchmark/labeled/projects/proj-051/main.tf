resource "aws_efs_file_system" "vuln" {
  encrypted = true
}

resource "aws_efs_file_system_policy" "p" {
  file_system_id = aws_efs_file_system.vuln.id
  policy         = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "elasticfilesystem:ClientMount",
      "Resource": "*"
    }
  ]
}
POLICY
}
