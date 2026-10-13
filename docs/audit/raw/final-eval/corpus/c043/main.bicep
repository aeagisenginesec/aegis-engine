// Hub VNet. Subnets and NSG rules are generated with loops; the
// contractors rule was left internet-wide after the migration weekend.
param location string = resourceGroup().location
param vnetName string = 'hub-vnet'
param addressPrefix string = '10.60.0.0/16'

var subnets = [
  { name: 'app', prefix: '10.60.1.0/24' }
  { name: 'data', prefix: '10.60.2.0/24' }
  { name: 'contractors', prefix: '10.60.9.0/24' }
]

var baseRules = [
  {
    name: 'Allow-VNet-Internal'
    priority: 100
    port: '*'
    source: 'VirtualNetwork'
  }
  {
    name: 'Allow-Contractor-RDP'
    priority: 200
    port: '3389'
    source: '*'
  }
]

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${vnetName}-nsg'
  location: location
  properties: {
    securityRules: [
      for rule in baseRules: {
        name: rule.name
        properties: {
          priority: rule.priority
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: rule.port
          sourceAddressPrefix: rule.source
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [addressPrefix]
    }
    subnets: [
      for s in subnets: {
        name: s.name
        properties: {
          addressPrefix: s.prefix
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

output vnetId string = vnet.id
