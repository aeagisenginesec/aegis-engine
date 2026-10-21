resource data 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'data259d8d'
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
  name: 'kv-259d8d'
  location: 'westeurope'
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: '00000000-0000-0000-0000-000000000000'
    enablePurgeProtection: true
    enableSoftDelete: true
    accessPolicies: []
  }
}

param names array = ['store259d8da', 'store259d8db']
resource stores 'Microsoft.Storage/storageAccounts@2023-01-01' = [for n in names: {
  name: n
  location: 'westeurope'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}]
