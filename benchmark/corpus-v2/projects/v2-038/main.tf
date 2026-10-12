resource "aws_cognito_identity_pool" "mobile" {
  identity_pool_name               = "mobile"
  allow_unauthenticated_identities = true
}
