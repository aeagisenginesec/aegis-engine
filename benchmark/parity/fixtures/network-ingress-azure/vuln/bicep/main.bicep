resource nsg 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: 'parity-nsg'
  location: 'westeurope'
  properties: {
    securityRules: [
      {
        name: 'allow-all-inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}
