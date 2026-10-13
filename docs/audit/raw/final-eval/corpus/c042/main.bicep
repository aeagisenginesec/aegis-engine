// Production secrets vault: RBAC-only, purge protection, deny-by-default network rules.
param location string = resourceGroup().location
param vaultName string = 'prodsecrets${uniqueString(resourceGroup().id)}'
param retentionDays int = 90

var skuName = 'premium'

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: skuName
    }
    enableSoftDelete: true
    softDeleteRetentionInDays: retentionDays
    enablePurgeProtection: true
    enableRbacAuthorization: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

resource seedSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  name: 'db-password'
  parent: vault
  properties: {
    value: 'PLACEHOLDER_ROTATE_ME'
    contentType: 'database credential'
  }
}

output vaultUri string = vault.properties.vaultUri
