targetScope = 'subscription'

// Production subscription landing zone: resource group with enforced tags
// and a delete lock so it cannot be removed by accident.
param location string = 'westeurope'
param workload string = 'payments'

var rgName = 'rg-${workload}-prod'
var requiredTags = {
  environment: 'prod'
  workload: workload
  costCenter: 'fin-042'
  dataClassification: 'confidential'
}

resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: rgName
  location: location
  tags: requiredTags
}

resource lock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: '${rgName}-cannot-delete'
  scope: rg
  properties: {
    level: 'CanNotDelete'
    notes: 'Production resource group: deletion requires CAB approval.'
  }
}

output resourceGroupId string = rg.id
