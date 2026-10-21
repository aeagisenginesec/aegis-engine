package bicep

import (
	"strings"
	"testing"
)

// Adapter audit 2026-10-14: a NUL byte inside a Bicep string literal is
// silently kept in the parsed value, so comparisons against security
// sentinel values ('*', '0.0.0.0/0') fail and findings vanish with NO
// diagnostic. Repro: an NSG rule with sourceAddressPrefix '<NUL>*' yields
// zero findings while the identical file without the NUL yields
// AEGIS-AZURE-053/054/055/244. Sibling adapters are honest here:
// dockerfile strips NULs with a warning (item6b), terraform hard-errors,
// and the YAML/JSON adapters error via their decoders. Bicep does neither.
//
// This test pins the desired honest behavior: a null-bytes diagnostic.
// It is skipped until the adapter handles NUL bytes; unskip when fixed.
func TestAuditNulByteEmitsDiagnostic(t *testing.T) {
	// Fixed 2026-10-14: the adapter now strips NUL bytes with a warning
	// diagnostic instead of silently keeping them (which suppressed
	// sentinel-value findings).
	src := "resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {\n" +
		"  name: 'nsg1'\n" +
		"  location: 'westeurope'\n" +
		"  properties: {\n" +
		"    securityRules: [\n" +
		"      {\n" +
		"        name: 'open'\n" +
		"        properties: {\n" +
		"          access: 'Allow'\n" +
		"          direction: 'Inbound'\n" +
		"          sourceAddressPrefix: '\x00*'\n" +
		"          destinationPortRange: '*'\n" +
		"          protocol: '*'\n" +
		"        }\n" +
		"      }\n" +
		"    ]\n" +
		"  }\n" +
		"}\n"
	_, diags, err := New().Parse("main.bicep", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	for _, d := range diags {
		if strings.Contains(strings.ToLower(d.Message), "null") {
			return // honest: NUL bytes surfaced as a diagnostic
		}
	}
	t.Fatalf("expected a null-bytes diagnostic, got %+v", diags)
}
