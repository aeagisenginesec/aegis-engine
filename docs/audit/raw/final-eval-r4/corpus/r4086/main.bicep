param names array = ['store7b7f4ea', 'store7b7f4eb']
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
