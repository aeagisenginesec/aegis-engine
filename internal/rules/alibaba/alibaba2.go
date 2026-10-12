// Package alibaba — rules round 2 (AEGIS-ALI-007..012).
//
// Covers RAM policy least-privilege, ECS disk encryption, security group
// ingress, RDS transparent data encryption, ALB-family access logging, and
// ActionTrail event capture.
//
// Absent-attribute policy for this file: an absent attribute yields a
// finding when the provider default is the insecure one (disk unencrypted,
// TDE off, no access log config, ActionTrail capturing writes only).
// Present-but-unresolved values yield NO finding.
package alibaba

import (
	"strings"

	"aegis/internal/ir"
)

// Alibaba2Rules returns Alibaba Cloud rules 007..012 in ID order.
func Alibaba2Rules() []ir.Rule {
	return []ir.Rule{
		ramPolicyWildcard{},  // AEGIS-ALI-007
		ecsDiskUnencrypted{}, // AEGIS-ALI-008
		sgOpenIngress{},      // AEGIS-ALI-009
		rdsNoTDE{},           // AEGIS-ALI-010
		albNoAccessLog{},     // AEGIS-ALI-011
		actionTrailNarrow{},  // AEGIS-ALI-012
	}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-007: RAM policy grants wildcard actions
// ---------------------------------------------------------------------------

type ramPolicyWildcard struct{}

func (ramPolicyWildcard) ID() string { return "AEGIS-ALI-007" }
func (ramPolicyWildcard) Title() string {
	return "RAM policy grants wildcard actions"
}
func (ramPolicyWildcard) Description() string {
	return "alicloud_ram_policy whose policy_document allows Action \"*\" " +
		"grants full administrative power over every Alibaba Cloud service, " +
		"violating least privilege. Scope actions to the APIs the workload " +
		"actually needs."
}
func (ramPolicyWildcard) Severity() ir.Severity { return ir.SeverityCritical }

func (ramPolicyWildcard) AppliesTo(resType string) bool {
	return resType == "alicloud_ram_policy"
}

// hasWildcardAction reports whether a RAM policy document (JSON text, as
// produced by jsonencode or a heredoc) allows the "*" action.
func hasWildcardAction(doc string) bool {
	flat := strings.ToLower(doc)
	flat = strings.Join(strings.Fields(flat), "")
	return strings.Contains(flat, `"action":"*"`) ||
		strings.Contains(flat, `"action":["*"]`)
}

func (s ramPolicyWildcard) Check(r ir.Resource) []ir.Finding {
	doc, span, present, known := getString(r, "policy_document")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !hasWildcardAction(doc) {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "policy_document", span,
		"policy allows Action \"*\"",
		"scope Action to specific APIs, e.g. [\"oss:GetObject\"]")}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-008: ECS disk without encryption
// ---------------------------------------------------------------------------

type ecsDiskUnencrypted struct{}

func (ecsDiskUnencrypted) ID() string { return "AEGIS-ALI-008" }
func (ecsDiskUnencrypted) Title() string {
	return "ECS disk without encryption"
}
func (ecsDiskUnencrypted) Description() string {
	return "alicloud_ecs_disk without encrypted = true, or an " +
		"alicloud_instance data_disks entry without encryption, stores data " +
		"unencrypted at rest. Enable disk encryption (optionally with a " +
		"KMS key via kms_key_id)."
}
func (ecsDiskUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (ecsDiskUnencrypted) AppliesTo(resType string) bool {
	return resType == "alicloud_ecs_disk" || resType == "alicloud_instance"
}

func (s ecsDiskUnencrypted) Check(r ir.Resource) []ir.Finding {
	switch r.Type {
	case "alicloud_ecs_disk":
		enc, span, present, known := getBool(r, "encrypted")
		if present && !known {
			return nil
		}
		if present && enc {
			return nil
		}
		actual := "false"
		if !present {
			actual = "absent (provider default: false)"
		}
		return []ir.Finding{mkFinding(s, r, "encrypted",
			evidenceSpan(span, r.Span), actual, "encrypted = true")}
	case "alicloud_instance":
		blks, span, present, known := getBlocks(r, "data_disks")
		if !present || !known {
			return nil // no data disks declared or unresolved
		}
		var out []ir.Finding
		for _, b := range blks {
			enc, espan, epresent, eknown := blockBool(b, "encrypted")
			if epresent && !eknown {
				continue
			}
			if epresent && enc {
				continue
			}
			actual := "false"
			if !epresent {
				actual = "absent (default false)"
			}
			out = append(out, mkFinding(s, r, "data_disks",
				evidenceSpan(espan, evidenceSpan(span, r.Span)),
				"data_disks entry "+actual,
				"data_disks { encrypted = true }"))
		}
		return out
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-009: ECS security group rule open to the world
// ---------------------------------------------------------------------------

type sgOpenIngress struct{}

func (sgOpenIngress) ID() string { return "AEGIS-ALI-009" }
func (sgOpenIngress) Title() string {
	return "ECS security group rule open to the world"
}
func (sgOpenIngress) Description() string {
	return "alicloud_security_group_rule with type = \"ingress\", policy = " +
		"\"accept\" and cidr_ip = \"0.0.0.0/0\" permits traffic from the " +
		"entire internet. Restrict ingress to known source ranges."
}
func (sgOpenIngress) Severity() ir.Severity { return ir.SeverityCritical }

func (sgOpenIngress) AppliesTo(resType string) bool {
	return resType == "alicloud_security_group_rule"
}

func (s sgOpenIngress) Check(r ir.Resource) []ir.Finding {
	typ, _, tpresent, tknown := getString(r, "type")
	if !tpresent || !tknown {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(typ), "ingress") {
		return nil
	}
	pol, _, ppresent, pknown := getString(r, "policy")
	if ppresent && pknown && !strings.EqualFold(strings.TrimSpace(pol), "accept") {
		return nil // explicit drop: compliant
	}
	cidr, span, cpresent, cknown := getString(r, "cidr_ip")
	if !cpresent || !cknown {
		return nil
	}
	if strings.TrimSpace(cidr) != "0.0.0.0/0" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "cidr_ip", span, "0.0.0.0/0",
		"restrict cidr_ip to known source ranges")}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-010: RDS instance without transparent data encryption
// ---------------------------------------------------------------------------

type rdsNoTDE struct{}

func (rdsNoTDE) ID() string { return "AEGIS-ALI-010" }
func (rdsNoTDE) Title() string {
	return "RDS instance without transparent data encryption"
}
func (rdsNoTDE) Description() string {
	return "alicloud_db_instance without tde_status = \"Enabled\" stores " +
		"database files unencrypted at rest. Enable TDE so data files are " +
		"encrypted with a KMS key."
}
func (rdsNoTDE) Severity() ir.Severity { return ir.SeverityHigh }

func (rdsNoTDE) AppliesTo(resType string) bool {
	return resType == "alicloud_db_instance"
}

func (s rdsNoTDE) Check(r ir.Resource) []ir.Finding {
	status, span, present, known := getString(r, "tde_status")
	if present && !known {
		return nil
	}
	if present && strings.EqualFold(strings.TrimSpace(status), "Enabled") {
		return nil
	}
	actual := "absent (TDE disabled)"
	if present {
		actual = status
	}
	return []ir.Finding{mkFinding(s, r, "tde_status",
		evidenceSpan(span, r.Span), actual, "tde_status = \"Enabled\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-011: ALB load balancer without access logging
// ---------------------------------------------------------------------------

type albNoAccessLog struct{}

func (albNoAccessLog) ID() string { return "AEGIS-ALI-011" }
func (albNoAccessLog) Title() string {
	return "ALB load balancer without access logging"
}
func (albNoAccessLog) Description() string {
	return "alicloud_alb_load_balancer without an access_log_config block " +
		"produces no request logs, leaving load-balancer traffic unaudited. " +
		"Configure access_log_config with a Log Service project and store."
}
func (albNoAccessLog) Severity() ir.Severity { return ir.SeverityMedium }

func (albNoAccessLog) AppliesTo(resType string) bool {
	return resType == "alicloud_alb_load_balancer"
}

func (s albNoAccessLog) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "access_log_config")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "access_log_config",
		evidenceSpan(span, r.Span), "absent (no access logging)",
		"access_log_config { log_project = \"...\" log_store = \"...\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-012: ActionTrail trail without full event capture
// ---------------------------------------------------------------------------

type actionTrailNarrow struct{}

func (actionTrailNarrow) ID() string { return "AEGIS-ALI-012" }
func (actionTrailNarrow) Title() string {
	return "ActionTrail trail without full event capture"
}
func (actionTrailNarrow) Description() string {
	return "alicloud_actiontrail_trail without event_rw = \"All\" captures " +
		"only write (or read) events instead of the full API audit trail. " +
		"Set event_rw = \"All\" so every management event is delivered to " +
		"OSS/SLS for investigation."
}
func (actionTrailNarrow) Severity() ir.Severity { return ir.SeverityMedium }

func (actionTrailNarrow) AppliesTo(resType string) bool {
	return resType == "alicloud_actiontrail_trail"
}

func (s actionTrailNarrow) Check(r ir.Resource) []ir.Finding {
	rw, span, present, known := getString(r, "event_rw")
	if present && !known {
		return nil
	}
	if present && strings.EqualFold(strings.TrimSpace(rw), "All") {
		return nil
	}
	actual := "absent (provider default: Write)"
	if present {
		actual = rw
	}
	return []ir.Finding{mkFinding(s, r, "event_rw",
		evidenceSpan(span, r.Span), actual, "event_rw = \"All\"")}
}
