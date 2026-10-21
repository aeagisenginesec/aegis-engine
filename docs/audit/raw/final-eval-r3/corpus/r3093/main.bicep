resource legacy 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'legacy4244b6'
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
  name: 'data4244b6'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}
