package azure

import (
	"testing"

	"aegis/internal/ir"
)

// TestAZURE044_MssqlNoTDEFires verifies TDE detection.
func TestAZURE044_MssqlNoTDEFires(t *testing.T) {
	r := res("azurerm_mssql_server", "s", map[string]ir.Value{"transparent_data_encryption_enabled": kv(false, 3)})
	mustFinding(t, runRule(mssqlNoTDE{}, r), "AEGIS-AZURE-044")
}

func TestAZURE044_TDEQuiet(t *testing.T) {
	r := res("azurerm_mssql_server", "s", map[string]ir.Value{"transparent_data_encryption_enabled": kv(true, 3)})
	if len(runRule(mssqlNoTDE{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE049_NoTDEFires verifies TDE detection.
func TestAZURE049_NoTDEFires(t *testing.T) {
	r := res("azurerm_mssql_database", "d", map[string]ir.Value{"transparent_data_encryption_enabled": kv(false, 3)})
	mustFinding(t, runRule(mssqlDBNoTDE{}, r), "AEGIS-AZURE-049")
}

// TestAZURE049_TDEQuiet verifies an encrypted MSSQL database stays quiet.
func TestAZURE049_TDEQuiet(t *testing.T) {
	r := res("azurerm_mssql_database", "d", map[string]ir.Value{"transparent_data_encryption_enabled": kv(true, 3)})
	if len(runRule(mssqlDBNoTDE{}, r)) != 0 {
		t.Fatal("AEGIS-AZURE-049: expected 0 findings")
	}
}

// TestAZURE050_FirewallOpenFires verifies open firewall rule.
func TestAZURE050_FirewallOpenFires(t *testing.T) {
	r := res("azurerm_mssql_firewall_rule", "f", map[string]ir.Value{
		"start_ip_address": ks("0.0.0.0", 3),
		"end_ip_address":   ks("0.0.0.0", 4),
	})
	mustFinding(t, runRule(mssqlFirewallOpen{}, r), "AEGIS-AZURE-050")
}

func TestAZURE050_FirewallRestrictedQuiet(t *testing.T) {
	r := res("azurerm_mssql_firewall_rule", "f", map[string]ir.Value{
		"start_ip_address": ks("203.0.113.0", 3),
		"end_ip_address":   ks("203.0.113.255", 4),
	})
	if len(runRule(mssqlFirewallOpen{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE053_RDPPublicFires verifies RDP exposure.
func TestAZURE053_RDPPublicFires(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 4),
		"protocol":               ks("Tcp", 5),
		"destination_port_range": ks("3389", 6),
		"source_address_prefix":  ks("*", 7),
	})
	mustFinding(t, runRule(nsgRDPPublic{}, r), "AEGIS-AZURE-053")
}

func TestAZURE053_RDPPrivateQuiet(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 4),
		"protocol":               ks("Tcp", 5),
		"destination_port_range": ks("3389", 6),
		"source_address_prefix":  ks("10.0.0.0/8", 7),
	})
	if len(runRule(nsgRDPPublic{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE054_SSHPublicFires verifies SSH exposure.
func TestAZURE054_SSHPublicFires(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 4),
		"protocol":               ks("Tcp", 5),
		"destination_port_range": ks("22", 6),
		"source_address_prefix":  ks("0.0.0.0/0", 7),
	})
	mustFinding(t, runRule(nsgSSHPublic{}, r), "AEGIS-AZURE-054")
}

// TestAZURE054_SSHPrivateQuiet verifies SSH open to a private range stays quiet.
func TestAZURE054_SSHPrivateQuiet(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 4),
		"protocol":               ks("Tcp", 5),
		"destination_port_range": ks("22", 6),
		"source_address_prefix":  ks("10.0.0.0/8", 7),
	})
	if len(runRule(nsgSSHPublic{}, r)) != 0 {
		t.Fatal("AEGIS-AZURE-054: expected 0 findings")
	}
}

// TestAZURE055_WildcardPortFires verifies wildcard port detection.
func TestAZURE055_WildcardPortFires(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 4),
		"protocol":               ks("*", 5),
		"destination_port_range": ks("*", 6),
		"source_address_prefix":  ks("*", 7),
	})
	mustFinding(t, runRule(nsgWildcardPort{}, r), "AEGIS-AZURE-055")
}

// TestAZURE055_ScopedPortQuiet verifies a scoped destination port stays quiet.
func TestAZURE055_ScopedPortQuiet(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 4),
		"protocol":               ks("Tcp", 5),
		"destination_port_range": ks("443", 6),
		"source_address_prefix":  ks("0.0.0.0/0", 7),
	})
	if len(runRule(nsgWildcardPort{}, r)) != 0 {
		t.Fatal("AEGIS-AZURE-055: expected 0 findings")
	}
}

// TestAZURE057_NoDDoSFires verifies DDoS protection detection.
func TestAZURE057_NoDDoSFires(t *testing.T) {
	r := res("azurerm_virtual_network", "v", map[string]ir.Value{})
	mustFinding(t, runRule(vnetNoDDoS{}, r), "AEGIS-AZURE-057")
}

// TestAZURE060_NoServiceEndpointFires verifies service endpoint detection.
func TestAZURE060_NoServiceEndpointFires(t *testing.T) {
	r := res("azurerm_subnet", "s", map[string]ir.Value{})
	mustFinding(t, runRule(subnetNoServiceEndpoint{}, r), "AEGIS-AZURE-060")
}
