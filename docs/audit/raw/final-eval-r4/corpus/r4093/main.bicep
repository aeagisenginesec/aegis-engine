resource aks 'Microsoft.ContainerService/managedClusters@2023-05-01' = {
  name: 'aks-2669c8'
  location: 'westeurope'
  properties: {
    dnsPrefix: 'aks'
    enableRBAC: false
    agentPoolProfiles: [{ name: 'default' count: 1 vmSize: 'Standard_D2_v2' mode: 'System' }]
  }
}

resource data 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'data2669c8'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}
