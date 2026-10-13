// Landing-zone storage deployed through a shared module. The module is
// locked down, but this caller opts the container back into public access.
param location string = resourceGroup().location
param environment string = 'prod'

module appStorage 'modules/storage.bicep' = {
  name: 'appStorage'
  params: {
    location: location
    storageAccountName: 'app${environment}${uniqueString(resourceGroup().id)}'
    containerPublicAccess: 'Blob'
  }
}

output storageAccountId string = appStorage.outputs.storageAccountId
