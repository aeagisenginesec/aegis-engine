package arm

import (
	"testing"
)

// Phase B tests: ARM adapter gaps — MySQL flexible-server public-network
// promotion (P0-5), VM linuxConfiguration promotion (P0-6), and
// arm_parameter emission (P0-9).

const armMySQLFlex = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/flexibleServers",
      "apiVersion": "2023-12-30",
      "name": "mysql-demo",
      "location": "westeurope",
      "properties": {
        "version": "8.0.21",
        "network": {
          "publicNetworkAccess": "Enabled"
        }
      }
    }
  ]
}`

func TestPhaseB_MySQLFlexPublicNetworkPromoted(t *testing.T) {
	res := parseARM(t, armMySQLFlex)
	r := findResource(res, "azurerm_mysql_flexible_server")
	if r == nil {
		t.Fatalf("no azurerm_mysql_flexible_server; got %d resources", len(res))
	}
	if got := mustBool(t, r, "public_network_access_enabled"); !got {
		t.Errorf("public_network_access_enabled = false, want true (Enabled)")
	}
}

func TestPhaseB_MySQLFlexPublicNetworkDisabled(t *testing.T) {
	res := parseARM(t, `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/flexibleServers",
      "apiVersion": "2023-12-30",
      "name": "mysql-demo",
      "location": "westeurope",
      "properties": {
        "version": "8.0.21",
        "network": {
          "publicNetworkAccess": "Disabled"
        }
      }
    }
  ]
}`)
	r := findResource(res, "azurerm_mysql_flexible_server")
	if r == nil {
		t.Fatalf("no azurerm_mysql_flexible_server")
	}
	if got := mustBool(t, r, "public_network_access_enabled"); got {
		t.Errorf("public_network_access_enabled = true, want false (Disabled)")
	}
}

const armLinuxVM = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Compute/virtualMachines",
      "apiVersion": "2023-03-01",
      "name": "vm-demo",
      "location": "westeurope",
      "properties": {
        "osProfile": {
          "computerName": "vm-demo",
          "adminUsername": "azureuser",
          "linuxConfiguration": {
            "disablePasswordAuthentication": false
          }
        }
      }
    }
  ]
}`

func TestPhaseB_VMLinuxPasswordAuthPromoted(t *testing.T) {
	res := parseARM(t, armLinuxVM)
	r := findResource(res, "azurerm_virtual_machine")
	if r == nil {
		t.Fatalf("no azurerm_virtual_machine; got %d resources", len(res))
	}
	if got := mustBool(t, r, "disable_password_authentication"); got {
		t.Errorf("disable_password_authentication = true, want false")
	}
}

func TestPhaseB_VMWindowsNoPromotion(t *testing.T) {
	res := parseARM(t, `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Compute/virtualMachines",
      "apiVersion": "2023-03-01",
      "name": "vm-win",
      "location": "westeurope",
      "properties": {
        "osProfile": {
          "computerName": "vm-win",
          "adminUsername": "azureuser",
          "windowsConfiguration": {
            "enableAutomaticUpdates": true
          }
        }
      }
    }
  ]
}`)
	r := findResource(res, "azurerm_virtual_machine")
	if r == nil {
		t.Fatalf("no azurerm_virtual_machine")
	}
	if _, ok := r.Attributes["disable_password_authentication"]; ok {
		t.Errorf("Windows VM must not get disable_password_authentication promoted")
	}
}

const armParameters = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "dbPassword": {
      "type": "secureString",
      "defaultValue": "hunter2"
    },
    "environment": {
      "type": "string",
      "defaultValue": "prod"
    },
    "noDefault": {
      "type": "string"
    }
  },
  "resources": []
}`

func TestPhaseB_ParametersEmitted(t *testing.T) {
	res := parseARM(t, armParameters)
	var found []string
	for i := range res {
		if res[i].Type != "arm_parameter" {
			continue
		}
		found = append(found, res[i].Name)
		if res[i].Name == "dbPassword" {
			if got := mustString(t, &res[i], "type"); got != "secureString" {
				t.Errorf("dbPassword type = %q, want secureString", got)
			}
			if got := mustString(t, &res[i], "default"); got != "hunter2" {
				t.Errorf("dbPassword default = %q, want hunter2", got)
			}
		}
		if res[i].Name == "environment" {
			if got := mustString(t, &res[i], "type"); got != "string" {
				t.Errorf("environment type = %q, want string", got)
			}
			if got := mustString(t, &res[i], "default"); got != "prod" {
				t.Errorf("environment default = %q, want prod", got)
			}
		}
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 arm_parameter resources (noDefault has none), got %v", found)
	}
}
