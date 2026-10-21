// Shared storage module: hardened account, caller-controlled container ACL.
param location string
param storageAccountName string

@allowed(['None', 'Blob', 'Container'])
param containerPublicAccess string = 'None'

resource account 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  name: '${account.name}/default/uploads'
  properties: {
    publicAccess: containerPublicAccess
  }
}

output storageAccountId string = account.id
