resource "aws_s3_access_point" "reports" {
  name   = "reports-ap"
  bucket = "reports-bucket"
}

resource "aws_s3control_access_point_policy" "reports" {
  access_point_arn = aws_s3_access_point.reports.arn
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:us-east-1:123456789012:accesspoint/reports-ap/object/*"
    }
  ]
}
POLICY
}
