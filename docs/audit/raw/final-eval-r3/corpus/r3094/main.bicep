resource legacy 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'legacyb433b4'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: true
  }
}
