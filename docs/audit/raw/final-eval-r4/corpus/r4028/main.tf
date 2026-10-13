resource "aws_s3_bucket" "data" {
  bucket = "data-lake-65c84c"
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = "*"
      Action = "s3:GetObject"
      Resource = "arn:aws:s3:::data-lake-65c84c/*"
    }]
  })
}

resource "aws_lb" "web" {
  name = "web-65c84c"
  internal = false
  load_balancer_type = "application"
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port = 80
  protocol = "HTTP"
  default_action { type = "forward" target_group_arn = aws_lb_target_group.web.arn }
}

resource "aws_lb_target_group" "web" {
  port = 8080
  protocol = "HTTP"
  vpc_id = "vpc-12345678"
}
