package bicep

// Twin test for the Sprint 3 Bicep .id fix. A resource symbol's .id
// access (st.id) previously compiled to the resource's NAME fragment
// plus ".id", which the ARM evaluator reads as member access on a
// string literal and degrades to Unknown — so private-endpoint
// linkage (and any other cross-resource reference through .id) was
// invisible in Bicep while working in Terraform. It now compiles to
// resourceId('<type>', '<name>'), which the ARM evaluator surfaces
// as a reference.

import (
	"testing"

	"aegis/internal/ir"
)

const bicepWithIDRef = `
resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'idrefacct'
  location: 'westeurope'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
  }
}

resource pe 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'idrefacct-pe'
  location: 'westeurope'
  properties: {
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: st.id
          groupIds: ['blob']
        }
      }
    ]
  }
}
`

func TestBicepResourceIDBecomesRef(t *testing.T) {
	res, _, err := New().Parse("main.bicep", []byte(bicepWithIDRef))
	if err != nil {
		t.Fatal(err)
	}
	var pe *ir.Resource
	for i := range res {
		if res[i].Type == "azurerm_private_endpoint" {
			pe = &res[i]
		}
	}
	if pe == nil {
		t.Fatalf("no azurerm_private_endpoint in %v", res)
	}
	v, ok := pe.Attributes["private_link_service_connections"]
	if !ok {
		t.Fatalf("PE has no private_link_service_connections: %v", pe.Attributes)
	}
	conns, ok := v.Raw.([]ir.Value)
	if !ok || len(conns) == 0 {
		t.Fatalf("private_link_service_connections not a block list: %#v", v.Raw)
	}
	conn, _ := conns[0].Raw.(map[string]ir.Value)
	props, _ := conn["properties"].Raw.(map[string]ir.Value)
	idv, ok := props["private_link_service_id"]
	if !ok {
		t.Fatalf("private_link_service_id missing: %v", conn)
	}
	if !idv.IsRef() {
		t.Fatalf("st.id should surface as a reference, got %#v", idv)
	}
	if idv.Ref != "azurerm_storage_account.idrefacct.id" {
		t.Errorf("ref = %q, want azurerm_storage_account.idrefacct.id", idv.Ref)
	}
}
