// Shared parameters demo used by the platform team. Defaults are sane
// except the TLS version, which was never raised after the initial draft.
param location string = resourceGroup().location

@minLength(3)
@maxLength(24)
param workload string = 'shared'

@allowed(['dev', 'test', 'prod'])
param environment string = 'dev'

var storageAccountName = take('${workload}${environment}${uniqueString(resourceGroup().id)}', 24)
var tags = {
  workload: workload
  environment: environment
  managedBy: 'bicep'
}

resource data 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  tags: tags
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_0'
    allowBlobPublicAccess: false
    publicNetworkAccess: 'Enabled'
  }
}

resource uploads 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  name: '${data.name}/default/uploads'
  properties: {
    publicAccess: 'None'
  }
}

output storageAccountName string = data.name
