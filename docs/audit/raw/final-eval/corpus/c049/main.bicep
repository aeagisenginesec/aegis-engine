// Hardened NSG: office-only management ports, deny-all fallback.
param location string = resourceGroup().location
param nsgName string = 'prod-app-nsg'
param officeCidr string = '203.0.113.0/24'

var allowedMgmtPorts = [
  { port: '22', name: 'SSH' }
  { port: '3389', name: 'RDP' }
]

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: concat(
      [
        for svc in allowedMgmtPorts: {
          name: 'Allow-Office-${svc.name}'
          properties: {
            priority: svc.port == '22' ? 100 : 110
            direction: 'Inbound'
            access: 'Allow'
            protocol: 'Tcp'
            sourcePortRange: '*'
            destinationPortRange: svc.port
            sourceAddressPrefix: officeCidr
            destinationAddressPrefix: '*'
          }
        }
      ],
      [
        {
          name: 'Deny-All-Inbound'
          properties: {
            priority: 4096
            direction: 'Inbound'
            access: 'Deny'
            protocol: '*'
            sourcePortRange: '*'
            destinationPortRange: '*'
            sourceAddressPrefix: '*'
            destinationAddressPrefix: '*'
          }
        }
      ]
    )
  }
}

output nsgId string = nsg.id

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: 'prod-app-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.40.0.0/16']
    }
    subnets: [
      {
        name: 'app'
        properties: {
          addressPrefix: '10.40.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}
