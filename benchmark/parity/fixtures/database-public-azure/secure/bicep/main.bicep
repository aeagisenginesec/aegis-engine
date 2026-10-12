resource sql 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: 'parity-mssql'
  location: 'westeurope'
  properties: {
    administratorLogin: 'dbadmin'
    administratorLoginPassword: 'Hardcoded123!'
    publicNetworkAccess: 'Disabled'
  }
}
