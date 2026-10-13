terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_user" "deploy" {
  name = "deploy-bot"
}

resource "aws_iam_user_policy_attachment" "deploy_admin" {
  user       = aws_iam_user.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "deploy" {
  user = aws_iam_user.deploy.name
}

resource "aws_iam_user_policy" "deploy_wildcard" {
  name = "wildcard-inline"
  user = aws_iam_user.deploy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_group" "ops" {
  name = "ops-team"
}

resource "aws_iam_group_policy_attachment" "ops_admin" {
  group      = aws_iam_group.ops.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
