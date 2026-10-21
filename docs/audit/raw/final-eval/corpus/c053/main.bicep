// Spoke VNet peered to the hub with traffic forwarding on, and an NSG
// that allows everything inbound from the peered address space.
param location string = resourceGroup().location
param spokeName string = 'spoke-vnet'
param hubVnetId string

var peeredRange = '10.0.0.0/8'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${spokeName}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-Hub-All'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: peeredRange
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource spoke 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: spokeName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.70.0.0/16']
    }
    subnets: [
      {
        name: 'workload'
        properties: {
          addressPrefix: '10.70.0.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource toHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-09-01' = {
  name: 'to-hub'
  parent: spoke
  properties: {
    remoteVirtualNetwork: {
      id: hubVnetId
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

output spokeId string = spoke.id
