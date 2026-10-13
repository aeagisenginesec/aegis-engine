resource web 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'web-15de64'
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

resource legacy 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'legacy15de64'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: true
  }
}
