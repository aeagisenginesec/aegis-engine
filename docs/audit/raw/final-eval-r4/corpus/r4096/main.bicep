resource aks 'Microsoft.ContainerService/managedClusters@2023-05-01' = {
  name: 'aks-240006'
  location: 'westeurope'
  properties: {
    dnsPrefix: 'aks'
    enableRBAC: false
    agentPoolProfiles: [{ name: 'default' count: 1 vmSize: 'Standard_D2_v2' mode: 'System' }]
  }
}
