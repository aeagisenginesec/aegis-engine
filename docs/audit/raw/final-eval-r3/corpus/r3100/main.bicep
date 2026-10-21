resource web 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'web-be7fc9'
  location: 'westeurope'
  properties: {
    securityRules: [
      {
        name: 'allow-ssh'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-be7fc9'
  location: 'westeurope'
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: '00000000-0000-0000-0000-000000000000'
    enablePurgeProtection: false
    enableSoftDelete: true
    accessPolicies: []
  }
}
