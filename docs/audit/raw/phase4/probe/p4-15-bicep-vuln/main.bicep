resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'p4probebicep01'
  location: 'westeurope'
  properties: {
    tenantId: '00000000-0000-0000-0000-000000000000'
    sku: {
      family: 'A'
      name: 'standard'
    }
    accessPolicies: []
  }
}
