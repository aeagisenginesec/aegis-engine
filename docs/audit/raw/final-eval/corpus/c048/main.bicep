// Quick team vault for dev secrets.
param location string = resourceGroup().location
param vaultName string = 'devteam${uniqueString(resourceGroup().id)}'
param tenantId string = subscription().tenantId

@secure()
param deployerObjectId string

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableSoftDelete: false
    enablePurgeProtection: false
    enableRbacAuthorization: false
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
    accessPolicies: [
      {
        tenantId: tenantId
        objectId: deployerObjectId
        permissions: {
          keys: ['all']
          secrets: ['all']
          certificates: ['all']
        }
      }
    ]
  }
}

resource seedSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  name: 'api-key'
  parent: vault
  properties: {
    value: 'PLACEHOLDER_ROTATE_ME'
    contentType: 'third-party api key'
  }
}

output vaultUri string = vault.properties.vaultUri
