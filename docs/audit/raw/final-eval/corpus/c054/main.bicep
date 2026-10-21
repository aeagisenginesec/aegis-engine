// App vault seeded with rotated secrets via a loop. RBAC is on, but purge
// protection was skipped because the team feared lock-in.
param location string = resourceGroup().location
param vaultName string = 'appsecrets${uniqueString(resourceGroup().id)}'

var seedSecrets = [
  { name: 'db-password', contentType: 'database credential' }
  { name: 'api-key', contentType: 'third-party api key' }
  { name: 'smtp-password', contentType: 'email credential' }
]

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: false
    enableRbacAuthorization: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

resource secrets 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = [
  for s in seedSecrets: {
    name: s.name
    parent: vault
    properties: {
      value: 'PLACEHOLDER_ROTATE_ME'
      contentType: s.contentType
    }
  }
]

output vaultUri string = vault.properties.vaultUri
