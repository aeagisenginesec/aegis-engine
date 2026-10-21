// Genuinely compliant Bicep fixture (Sprint 3 FP-budget gate):
// the same hardened storage account as the ARM fixture — private,
// TLS 1.2+, HTTPS-only, soft delete and blob versioning on.
resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'aegiscompliantst'
  location: 'westeurope'
  sku: {
    name: 'Standard_GRS'
  }
  kind: 'StorageV2'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    publicNetworkAccess: 'Disabled'
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    accessTier: 'Hot'
    sasPolicy: {
      sasExpirationPeriod: '1.00:00:00'
      expirationAction: 'Block'
    }
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
      ipRules: []
      virtualNetworkRules: []
    }
    encryption: {
      keySource: 'Microsoft.Keyvault'
      keyVaultProperties: {
        keyVaultUri: 'https://aegis-compliant-vault.vault.azure.net/'
        keyName: 'storage-cmk'
        keyVersion: '0123456789abcdef0123456789abcdef'
      }
      requireInfrastructureEncryption: true
      services: {
        blob: { enabled: true }
        file: { enabled: true }
        queue: { enabled: true }
        table: { enabled: true }
      }
    }
  }
}

resource queueServices 'Microsoft.Storage/storageAccounts/queueServices@2023-01-01' = {
  parent: st
  name: 'default'
  properties: {
    analyticsLogging: {
      delete: true
      read: true
      write: true
      version: '1.0'
      retentionPolicy: { enabled: true, days: 10 }
    }
    hourMetrics: {
      enabled: true
      version: '1.0'
      includeAPIs: true
      retentionPolicy: { enabled: true, days: 10 }
    }
    minuteMetrics: {
      enabled: true
      version: '1.0'
      includeAPIs: true
      retentionPolicy: { enabled: true, days: 10 }
    }
  }
}

resource ddosPlan 'Microsoft.Network/ddosProtectionPlans@2023-05-01' = {
  name: 'aegis-ddos-plan'
  location: 'westeurope'
  properties: {}
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'aegis-compliant-vnet'
  location: 'westeurope'
  properties: {
    enableDdosProtection: true
    ddosProtectionPlan: {
      id: ddosPlan.id
    }
    dhcpOptions: {
      dnsServers: ['10.20.0.4', '10.20.0.5']
    }
    addressSpace: {
      addressPrefixes: ['10.20.0.0/16']
    }
    subnets: [
      {
        name: 'endpoints'
        properties: {
          addressPrefix: '10.20.1.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

resource blobPe 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'aegiscompliantst-blob-pe'
  location: 'westeurope'
  properties: {
    subnet: {
      id: vnet.properties.subnets[0].id
    }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: st.id
          groupIds: ['blob']
        }
      }
    ]
  }
}

resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: st
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 7 }
    containerDeleteRetentionPolicy: { enabled: true, days: 7 }
    isVersioningEnabled: true
    changeFeed: { enabled: true }
    restorePolicy: { enabled: true, days: 6 }
  }
}
