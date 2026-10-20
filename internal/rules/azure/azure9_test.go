package azure

import (
	"testing"

	"aegis/internal/ir"
)

func storageRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_storage_account", "s", attrs)
}

// TestAZURE119_PublicBlobDefaultFires verifies public blob access (strict).
// TestAZURE120_QueueLoggingAbsentFires verifies queue logging (strict).
func TestAZURE120_QueueLoggingAbsentFires(t *testing.T) {
	mustFinding(t, runRule(storageQueueNoLogging{}, storageRes(nil)), "AEGIS-AZURE-034")
}

func TestAZURE120_QueuePropsWithoutLoggingFires(t *testing.T) {
	r := storageRes(map[string]ir.Value{"queue_properties": blks(3, blk())})
	mustFinding(t, runRule(storageQueueNoLogging{}, r), "AEGIS-AZURE-034")
}

func TestAZURE120_LoggingQuiet(t *testing.T) {
	r := storageRes(map[string]ir.Value{
		"queue_properties": blks(3, blk("logging", blks(4, blk("read", kv(true, 5))))),
	})
	if len(runRule(storageQueueNoLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE121_TLSD defaultFires verifies TLS version (strict).
func TestAZURE121_TLSDDefaultFires(t *testing.T) {
	mustFinding(t, runRule(storageMinTLS2{}, storageRes(nil)), "AEGIS-AZURE-121")
}

func TestAZURE121_WeakTLSFires(t *testing.T) {
	r := storageRes(map[string]ir.Value{"min_tls_version": ks("TLS1_0", 3)})
	mustFinding(t, runRule(storageMinTLS2{}, r), "AEGIS-AZURE-121")
}

func TestAZURE121_TLS12Quiet(t *testing.T) {
	r := storageRes(map[string]ir.Value{"min_tls_version": ks("TLS1_2", 3)})
	if len(runRule(storageMinTLS2{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE122_PublicAccessDefaultFires verifies blob public access (strict).
func TestAZURE122_PublicAccessDefaultFires(t *testing.T) {
	mustFinding(t, runRule(storageBlobPublic2{}, storageRes(nil)), "AEGIS-AZURE-122")
}

func TestAZURE122_PublicTrueFires(t *testing.T) {
	r := storageRes(map[string]ir.Value{"allow_blob_public_access": kv(true, 3)})
	mustFinding(t, runRule(storageBlobPublic2{}, r), "AEGIS-AZURE-122")
}

func TestAZURE122_DisabledQuiet(t *testing.T) {
	r := storageRes(map[string]ir.Value{"allow_blob_public_access": kv(false, 3)})
	if len(runRule(storageBlobPublic2{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE123_SharedKeyDefaultFires verifies shared key access (strict).
func TestAZURE123_SharedKeyDefaultFires(t *testing.T) {
	mustFinding(t, runRule(storageSharedKeyAccess{}, storageRes(nil)), "AEGIS-AZURE-031")
}

func TestAZURE123_EnabledFires(t *testing.T) {
	r := storageRes(map[string]ir.Value{"shared_access_key_enabled": kv(true, 3)})
	mustFinding(t, runRule(storageSharedKeyAccess{}, r), "AEGIS-AZURE-031")
}

func TestAZURE123_DisabledQuiet(t *testing.T) {
	r := storageRes(map[string]ir.Value{"shared_access_key_enabled": kv(false, 3)})
	if len(runRule(storageSharedKeyAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE124_NoPrivateEndpointFires verifies cross-resource detection.
func TestAZURE124_NoPrivateEndpointFires(t *testing.T) {
	s := storageRes(nil)
	f := storageNoPrivateEndpoint{}.CheckAll([]ir.Resource{s})
	mustFinding(t, f, "AEGIS-AZURE-124")
}

func TestAZURE124_PrivateEndpointQuiet(t *testing.T) {
	s := res("azurerm_storage_account", "data", nil)
	pe := res("azurerm_private_endpoint", "pe", map[string]ir.Value{
		"private_service_connection": blks(3, blk(
			"private_connection_resource_id",
			ir.Value{Ref: "azurerm_storage_account.data.id", Known: false, Span: spanAt(4)},
		)),
	})
	f := storageNoPrivateEndpoint{}.CheckAll([]ir.Resource{s, pe})
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(f))
	}
}

func TestAZURE124_OtherEndpointStillFires(t *testing.T) {
	s := res("azurerm_storage_account", "data", nil)
	other := res("azurerm_storage_account", "other", nil)
	pe := res("azurerm_private_endpoint", "pe", map[string]ir.Value{
		"private_service_connection": blks(3, blk(
			"private_connection_resource_id",
			ir.Value{Ref: "azurerm_storage_account.other.id", Known: false, Span: spanAt(4)},
		)),
	})
	f := storageNoPrivateEndpoint{}.CheckAll([]ir.Resource{s, other, pe})
	if len(f) != 1 || f[0].Resource != "azurerm_storage_account.data" {
		t.Fatalf("expected 1 finding on data account, got %+v", f)
	}
}

// TestAZURE125_NoSasPolicyFires verifies SAS policy detection.
func TestAZURE125_NoSasPolicyFires(t *testing.T) {
	mustFinding(t, runRule(storageNoSasPolicy{}, storageRes(nil)), "AEGIS-AZURE-125")
}

func TestAZURE125_PolicyWithoutExpiryFires(t *testing.T) {
	r := storageRes(map[string]ir.Value{"sas_policy": blks(3, blk())})
	mustFinding(t, runRule(storageNoSasPolicy{}, r), "AEGIS-AZURE-125")
}

func TestAZURE125_PolicyQuiet(t *testing.T) {
	r := storageRes(map[string]ir.Value{
		"sas_policy": blks(3, blk("expiration_period", ks("90.00:00:00", 4))),
	})
	if len(runRule(storageNoSasPolicy{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE126_NoSoftDeleteFires verifies blob soft delete (strict).
func TestAZURE126_NoSoftDeleteFires(t *testing.T) {
	mustFinding(t, runRule(storageNoBlobSoftDelete{}, storageRes(nil)), "AEGIS-AZURE-029")
}

func TestAZURE126_ZeroDaysFires(t *testing.T) {
	r := storageRes(map[string]ir.Value{
		"blob_properties": blks(3, blk(
			"delete_retention_policy", blks(4, blk("days", ir.Value{Raw: float64(0), Known: true, Span: spanAt(5)})),
		)),
	})
	mustFinding(t, runRule(storageNoBlobSoftDelete{}, r), "AEGIS-AZURE-029")
}

func TestAZURE126_SoftDeleteQuiet(t *testing.T) {
	r := storageRes(map[string]ir.Value{
		"blob_properties": blks(3, blk(
			"delete_retention_policy", blks(4, blk("days", ir.Value{Raw: float64(7), Known: true, Span: spanAt(5)})),
		)),
	})
	if len(runRule(storageNoBlobSoftDelete{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
