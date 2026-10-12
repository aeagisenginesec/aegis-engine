package azure

import (
	"testing"

	"aegis/internal/ir"
)

// TestAZURE061_NoAuthFires verifies App Service auth detection.
func TestAZURE061_NoAuthFires(t *testing.T) {
	r := res("azurerm_app_service", "a", map[string]ir.Value{})
	mustFinding(t, runRule(appSvcNoAuth{}, r), "AEGIS-AZURE-061")
}

func TestAZURE061_AuthQuiet(t *testing.T) {
	r := res("azurerm_app_service", "a", map[string]ir.Value{
		"auth_settings": blks(3, blk("enabled", ks("true", 4))),
	})
	if len(runRule(appSvcNoAuth{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE062_NoIdentityFires verifies managed identity detection.
func TestAZURE062_NoIdentityFires(t *testing.T) {
	r := res("azurerm_app_service", "a", map[string]ir.Value{})
	mustFinding(t, runRule(appSvcNoManagedIdent{}, r), "AEGIS-AZURE-062")
}

// TestAZURE064_FtpsAllFires verifies FTPS detection.
func TestAZURE064_FtpsAllFires(t *testing.T) {
	r := res("azurerm_app_service", "a", map[string]ir.Value{
		"site_config": blks(3, blk("ftps_state", ks("AllAllowed", 4))),
	})
	mustFinding(t, runRule(appSvcFtpsAll{}, r), "AEGIS-AZURE-064")
}

func TestAZURE064_FtpsOnlyQuiet(t *testing.T) {
	r := res("azurerm_app_service", "a", map[string]ir.Value{
		"site_config": blks(3, blk("ftps_state", ks("FtpsOnly", 4))),
	})
	if len(runRule(appSvcFtpsAll{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE065_RemoteDebugFires verifies remote debugging detection.
func TestAZURE065_RemoteDebugFires(t *testing.T) {
	r := res("azurerm_app_service", "a", map[string]ir.Value{
		"site_config": blks(3, blk("remote_debugging_enabled", kv(true, 4))),
	})
	mustFinding(t, runRule(appSvcRemoteDebug{}, r), "AEGIS-AZURE-065")
}

// TestAZURE069_NoPrivateClusterFires verifies AKS private cluster.
func TestAZURE069_NoPrivateClusterFires(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{"private_cluster_enabled": kv(false, 3)})
	mustFinding(t, runRule(aksNoPrivateCluster{}, r), "AEGIS-AZURE-069")
}

func TestAZURE069_PrivateQuiet(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{"private_cluster_enabled": kv(true, 3)})
	if len(runRule(aksNoPrivateCluster{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE073_NoAutoUpgradeFires verifies AKS upgrade channel.
func TestAZURE073_NoAutoUpgradeFires(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{"automatic_upgrade_channel": ks("none", 3)})
	mustFinding(t, runRule(aksNoAutoUpgrade{}, r), "AEGIS-AZURE-073")
}

// TestAZURE077_NoDiskEncryptionFires verifies VM disk encryption.
func TestAZURE077_NoDiskEncryptionFires(t *testing.T) {
	r := res("azurerm_linux_virtual_machine", "v", map[string]ir.Value{
		"os_disk": blks(3, blk()),
	})
	mustFinding(t, runRule(vmNoDiskEncryption{}, r), "AEGIS-AZURE-077")
}

// TestAZURE079_PublicIPFires verifies public IP detection.
func TestAZURE079_PublicIPFires(t *testing.T) {
	r := res("azurerm_network_interface", "n", map[string]ir.Value{
		"ip_configuration": blks(3, blk("public_ip_address_id", ks("azurerm_public_ip.example.id", 4))),
	})
	mustFinding(t, runRule(vmNoBastionHost{}, r), "AEGIS-AZURE-079")
}

func TestAZURE079_NoPublicIPQuiet(t *testing.T) {
	r := res("azurerm_network_interface", "n", map[string]ir.Value{
		"ip_configuration": blks(3, blk()),
	})
	if len(runRule(vmNoBastionHost{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE080_NoPatchModeFires verifies patch mode.
func TestAZURE080_NoPatchModeFires(t *testing.T) {
	r := res("azurerm_linux_virtual_machine", "v", map[string]ir.Value{"patch_mode": ks("Manual", 3)})
	mustFinding(t, runRule(vmNoPatchMode{}, r), "AEGIS-AZURE-080")
}
