// Analytics SQL: auditing and TDE enabled, but the firewall rule still
// covers the whole internet for the data-science VPN range.
param location string = resourceGroup().location
param serverName string = 'analyticsql${uniqueString(resourceGroup().id)}'

@secure()
param adminPassword string
param adminLogin string = 'sqladmin'

resource server 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: serverName
  location: location
  properties: {
    administratorLogin: adminLogin
    administratorLoginPassword: adminPassword
    publicNetworkAccess: 'Enabled'
    minimalTlsVersion: '1.2'
  }
}

resource auditing 'Microsoft.Sql/servers/auditingSettings@2023-05-01-preview' = {
  name: 'default'
  parent: server
  properties: {
    state: 'Enabled'
    isAzureMonitorTargetEnabled: true
    retentionDays: 30
  }
}

resource vpnRule 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
  name: 'DataScienceVPN'
  parent: server
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'
  }
}

resource db 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  name: 'analytics'
  parent: server
  location: location
  sku: {
    name: 'S0'
    tier: 'Standard'
  }
}

resource tde 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-05-01-preview' = {
  name: 'current'
  parent: db
  properties: {
    state: 'Enabled'
  }
}

output serverFqdn string = server.properties.fullyQualifiedDomainName
