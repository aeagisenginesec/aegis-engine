resource "aws_eks_cluster" "main" {
  name = "main-6eca80"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster"
  vpc_config {
    subnet_ids = ["subnet-aaa", "subnet-bbb"]
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }
}

resource "aws_iam_user" "deployer" {
  name = "deployer-6eca80"
}

resource "aws_iam_user_policy" "deployer" {
  user = aws_iam_user.deployer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "*"
      Resource = "*"
    }]
  })
}
