// Central Log Analytics workspace. Retention meets policy, but public
// ingestion was left enabled instead of using private link.
param location string = resourceGroup().location
param workspaceName string = 'central-logs-${uniqueString(resourceGroup().id)}'

@allowed([30, 60, 90, 120])
param retentionDays int = 90

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionDays
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

output workspaceId string = workspace.id

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'platform-alerts-ag'
  location: 'global'
  properties: {
    groupShortName: 'plat-alert'
    enabled: true
    emailReceivers: [
      {
        name: 'soc-email'
        emailAddress: 'soc@example.com'
        useCommonAlertSchema: true
      }
    ]
  }
}
