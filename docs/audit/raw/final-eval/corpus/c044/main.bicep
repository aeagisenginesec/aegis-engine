// SQL Server for the legacy ERP; vendor asked for open firewall access.
param location string = resourceGroup().location
param serverName string = 'erpsql${uniqueString(resourceGroup().id)}'

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
    minimalTlsVersion: '1.0'
  }
}

resource allowAll 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
  name: 'AllowAll'
  parent: server
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'
  }
}

resource db 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  name: 'erp'
  parent: server
  location: location
  sku: {
    name: 'S1'
    tier: 'Standard'
  }
}

output serverFqdn string = server.properties.fullyQualifiedDomainName
