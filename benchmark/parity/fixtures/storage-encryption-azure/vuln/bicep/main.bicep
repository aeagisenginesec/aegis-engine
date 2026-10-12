param location string = resourceGroup().location

resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'parityencst'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
}
