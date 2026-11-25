package azure

import (
	"testing"

	"aegis/internal/ir"
)

// Phase B tests: AEGIS-AZURE-315 (MySQL flexible server public access),
// AEGIS-AZURE-316 (SecureString parameter hardcoded default), and the
// AEGIS-AZURE-024 extension to azurerm_virtual_machine (ARM VMs).

// AEGIS-AZURE-315.

func TestAzure315_MySQLPublicFires(t *testing.T) {
	r := res("azurerm_mysql_flexible_server", "main", map[string]ir.Value{
		"public_network_access_enabled": kv(true, 2),
	})
	mustFinding(t, runRule(mysqlFlexPublicNet{}, r), "AEGIS-AZURE-315")
}

func TestAzure315_MySQLAbsentFires(t *testing.T) {
	// Provider default is public access enabled.
	r := res("azurerm_mysql_flexible_server", "main", nil)
	mustFinding(t, runRule(mysqlFlexPublicNet{}, r), "AEGIS-AZURE-315")
}

func TestAzure315_MySQLDisabledQuiet(t *testing.T) {
	r := res("azurerm_mysql_flexible_server", "main", map[string]ir.Value{
		"public_network_access_enabled": kv(false, 2),
	})
	if f := runRule(mysqlFlexPublicNet{}, r); len(f) != 0 {
		t.Fatalf("disabled public access must stay quiet, got %+v", f)
	}
}

func TestAzure315_MySQLUnknownQuiet(t *testing.T) {
	r := res("azurerm_mysql_flexible_server", "main", map[string]ir.Value{
		"public_network_access_enabled": ku(2),
	})
	if f := runRule(mysqlFlexPublicNet{}, r); len(f) != 0 {
		t.Fatalf("unknown value must stay quiet, got %+v", f)
	}
}

// AEGIS-AZURE-316.

func TestAzure316_SecureStringDefaultFires(t *testing.T) {
	r := res("arm_parameter", "dbAdminPassword", map[string]ir.Value{
		"type":    ks("secureString", 2),
		"default": ks("hunter2", 2),
	})
	f := mustFinding(t, runRule(armParameterSecret{}, r), "AEGIS-AZURE-316")
	if f.Evidence.Actual == "hunter2" {
		t.Fatalf("secret value must be redacted in evidence: %q", f.Evidence.Actual)
	}
}

func TestAzure316_SecureObjectDefaultFires(t *testing.T) {
	r := res("arm_parameter", "config", map[string]ir.Value{
		"type":    ks("secureObject", 2),
		"default": ks("{\"key\":\"abc\"}", 2),
	})
	mustFinding(t, runRule(armParameterSecret{}, r), "AEGIS-AZURE-316")
}

func TestAzure316_SecretNamePlainTypeFires(t *testing.T) {
	// Secret-like name is enough even with a plain string type.
	r := res("arm_parameter", "apiToken", map[string]ir.Value{
		"type":    ks("string", 2),
		"default": ks("tok_live_abc", 2),
	})
	mustFinding(t, runRule(armParameterSecret{}, r), "AEGIS-AZURE-316")
}

func TestAzure316_PlainParameterQuiet(t *testing.T) {
	r := res("arm_parameter", "environment", map[string]ir.Value{
		"type":    ks("string", 2),
		"default": ks("prod", 2),
	})
	if f := runRule(armParameterSecret{}, r); len(f) != 0 {
		t.Fatalf("plain parameter must stay quiet, got %+v", f)
	}
}

func TestAzure316_EmptyDefaultQuiet(t *testing.T) {
	r := res("arm_parameter", "dbAdminPassword", map[string]ir.Value{
		"type":    ks("secureString", 2),
		"default": ks("", 2),
	})
	if f := runRule(armParameterSecret{}, r); len(f) != 0 {
		t.Fatalf("empty default must stay quiet, got %+v", f)
	}
}

func TestAzure316_PlaceholderQuiet(t *testing.T) {
	r := res("arm_parameter", "dbAdminPassword", map[string]ir.Value{
		"type":    ks("secureString", 2),
		"default": ks("changeme", 2),
	})
	if f := runRule(armParameterSecret{}, r); len(f) != 0 {
		t.Fatalf("placeholder default must stay quiet, got %+v", f)
	}
}

func TestAzure316_KeyVaultRefQuiet(t *testing.T) {
	r := res("arm_parameter", "dbAdminPassword", map[string]ir.Value{
		"type":    ks("secureString", 2),
		"default": ks("https://myvault.vault.azure.net/secrets/dbpass", 2),
	})
	if f := runRule(armParameterSecret{}, r); len(f) != 0 {
		t.Fatalf("Key Vault reference must stay quiet, got %+v", f)
	}
}

// AEGIS-AZURE-024 extended to azurerm_virtual_machine (ARM).

func TestAzure024_ARMVMPasswordAuthFires(t *testing.T) {
	r := res("azurerm_virtual_machine", "main", map[string]ir.Value{
		"disable_password_authentication": kv(false, 2),
	})
	mustFinding(t, runRule(vmPasswordAuth{}, r), "AEGIS-AZURE-024")
}

func TestAzure024_ARMVMKeysOnlyQuiet(t *testing.T) {
	r := res("azurerm_virtual_machine", "main", map[string]ir.Value{
		"disable_password_authentication": kv(true, 2),
	})
	if f := runRule(vmPasswordAuth{}, r); len(f) != 0 {
		t.Fatalf("keys-only VM must stay quiet, got %+v", f)
	}
}

func TestAzure024_LinuxVMStillFires(t *testing.T) {
	r := res("azurerm_linux_virtual_machine", "main", map[string]ir.Value{
		"disable_password_authentication": kv(false, 2),
	})
	mustFinding(t, runRule(vmPasswordAuth{}, r), "AEGIS-AZURE-024")
}
