resource kvSecure187 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-secure-187'
  location: 'eastus'
  properties: {
    tenantId: '00000000-0000-0000-0000-000000000000'
    sku: {
      family: 'A'
      name: 'standard'
    }
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
  }
}
