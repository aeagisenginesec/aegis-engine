resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-96a14f'
  location: 'westeurope'
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: '00000000-0000-0000-0000-000000000000'
    enablePurgeProtection: false
    enableSoftDelete: true
    accessPolicies: []
  }
}
