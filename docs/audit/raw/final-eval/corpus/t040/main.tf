terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}
resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.dns_prefix
  private_cluster_enabled = true

  default_node_pool {
    name                         = "system"
    node_count                   = 3
    vm_size                      = "Standard_D4s_v5"
    vnet_subnet_id               = azurerm_subnet.system.id
    only_critical_addons_enabled = true
    os_disk_size_gb              = 128
  }

  identity {
    type = "SystemAssigned"
  }

  role_based_access_control_enabled = true

  azure_active_directory_role_based_access_control {
    managed            = true
    tenant_id          = var.tenant_id
    azure_rbac_enabled = true
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
  }

  oms_agent {
    log_analytics_workspace_id = var.log_analytics_id
  }

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }
}
