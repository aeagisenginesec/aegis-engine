resource aks 'Microsoft.ContainerService/managedClusters@2023-05-01' = {
  name: 'aks-491ac9'
  location: 'westeurope'
  properties: {
    dnsPrefix: 'aks'
    enableRBAC: false
    agentPoolProfiles: [{ name: 'default' count: 1 vmSize: 'Standard_D2_v2' mode: 'System' }]
  }
}

resource data 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'data491ac9'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-491ac9'
  location: 'westeurope'
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: '00000000-0000-0000-0000-000000000000'
    enablePurgeProtection: true
    enableSoftDelete: true
    accessPolicies: []
  }
}
