// Media storage for the public gallery app.
param location string = resourceGroup().location
param storageAccountName string = 'acmegallery${uniqueString(resourceGroup().id)}'

resource gallery 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
    allowBlobPublicAccess: true
    publicNetworkAccess: 'Enabled'
    accessTier: 'Hot'
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  name: '${gallery.name}/default/gallery-images'
  properties: {
    publicAccess: 'Blob'
  }
}

output storageAccountId string = gallery.id
