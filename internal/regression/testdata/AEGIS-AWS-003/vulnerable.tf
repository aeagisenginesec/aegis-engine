resource "aws_s3_bucket" "vuln" {
}

resource "aws_s3_bucket_policy" "vuln" {
  bucket = aws_s3_bucket.vuln.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::vuln/*"
    }
  ]
}
POLICY
}
