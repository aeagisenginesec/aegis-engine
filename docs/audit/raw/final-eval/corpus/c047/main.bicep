// Audit storage with diagnostic settings. Logging is on but retention is
// only 7 days, below the 90-day policy the compliance team expects.
param location string = resourceGroup().location
param storageAccountName string = 'audit${uniqueString(resourceGroup().id)}'
param workspaceId string

resource audit 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'storage-diagnostics'
  scope: audit
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        category: 'StorageRead'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 7
        }
      }
      {
        category: 'StorageWrite'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 7
        }
      }
    ]
    metrics: [
      {
        category: 'Transaction'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 7
        }
      }
    ]
  }
}

output storageAccountId string = audit.id
