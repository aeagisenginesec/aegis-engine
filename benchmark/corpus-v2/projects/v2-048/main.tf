resource "aws_cloudfront_distribution" "assets" {
  enabled = true

  origin {
    domain_name = "assets.example.s3.amazonaws.com"
    origin_id   = "s3-assets"
  }

  default_cache_behavior {
    target_origin_id       = "s3-assets"
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA"]
    }
  }
  logging_config {
    bucket = "cf-logs.example.s3.amazonaws.com"
    prefix = "cf/"
  }
  web_acl_id = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/cf-guard/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
  viewer_certificate {
    cloudfront_default_certificate = false
    acm_certificate_arn            = "arn:aws:acm:us-east-1:123456789012:certificate/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
    ssl_support_method             = "sni-only"
  }
}
