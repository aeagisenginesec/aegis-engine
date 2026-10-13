resource "azurerm_kubernetes_cluster_node_pool" "user" {
  name                  = "user"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_D8s_v5"
  node_count            = 3
  vnet_subnet_id        = azurerm_subnet.user.id
  mode                  = "User"
  os_disk_size_gb       = 128

  node_taints = [
    "workload=user:NoSchedule"
  ]

  tags = {
    pool = "user"
  }
}
