resource "aws_eks_cluster" "main" {
  name = "main-84c24a"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster"
  vpc_config {
    subnet_ids = ["subnet-aaa", "subnet-bbb"]
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }
}

resource "azurerm_storage_account" "legacy" {
  name = "legacy84c24a"
  resource_group_name = "rg-legacy"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_0"
}
