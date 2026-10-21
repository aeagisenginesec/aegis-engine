resource "aws_instance" "web" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
    http_endpoint = "enabled"
  }
  tags = { Name = "web-86a5fc" }
}

resource "aws_iam_user" "reader" {
  name = "reader-86a5fc"
}

resource "aws_iam_user_policy" "reader" {
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::reports-86a5fc",
       "arn:aws:s3:::reports-86a5fc/*"]
    }]
  })
}
