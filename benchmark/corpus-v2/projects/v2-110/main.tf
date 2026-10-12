resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = "app.example.com"
    origin_id   = "app"
  }
  default_cache_behavior {
    target_origin_id       = "app"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }
  viewer_certificate {
    acm_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/abc"
    ssl_support_method  = "sni-only"
  }
  logging_config {
    bucket = "cdn-logs-bucket.s3.amazonaws.com"
    prefix = "cdn/"
  }
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "MA"]
    }
  }

}
