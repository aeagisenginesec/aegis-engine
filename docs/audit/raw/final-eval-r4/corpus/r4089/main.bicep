resource legacy 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'legacy4f14d9'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: true
  }
}

resource data 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'data4f14d9'
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
  name: 'kv-4f14d9'
  location: 'westeurope'
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: '00000000-0000-0000-0000-000000000000'
    enablePurgeProtection: true
    enableSoftDelete: true
    accessPolicies: []
  }
}
