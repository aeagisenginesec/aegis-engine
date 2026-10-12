resource nsg 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: 'parity-nsg'
  location: 'westeurope'
  properties: {
    securityRules: [
      {
        name: 'allow-internal-inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '10.0.0.0/8'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}
