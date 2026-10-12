// Package gcp — expansion round 7 (AEGIS-GCP-183..222).
//
// Covers: GCS bucket hardening gaps, BigQuery access/encryption, Cloud Run
// v2 and Cloud Functions (gen1/gen2) configuration, Pub/Sub reliability and
// residency, and compute networking (backend services, firewalls,
// subnetworks, NAT, SSL policies, target pools, VPC mode).
//
// NOTE: IDs AEGIS-GCP-143..182 are reserved for the GCP6 expansion and are
// registered separately via GCP6Rules(); this file only owns 183..222.
//
// Absent-attribute policy for this file: an absent attribute yields a
// finding only when the provider default is the insecure one (documented
// per rule). Present-but-unresolved values yield NO finding. Rules never
// panic on unexpected shapes.
package gcp

import (
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// GCP7Rules returns GCP expansion rules 183..222 in ID order.
func GCP7Rules() []ir.Rule {
	return []ir.Rule{
		bucketNoSoftDelete{},       // AEGIS-GCP-183
		bucketVersioningNoLife{},   // AEGIS-GCP-184
		bucketIAMPolicyPublic{},    // AEGIS-GCP-185
		bucketDefObjACLPublic{},    // AEGIS-GCP-186
		bucketRetentionUnlocked{},  // AEGIS-GCP-187
		bucketIAMDomainAdmin{},     // AEGIS-GCP-188
		bucketCORSInsecureOrigin{}, // AEGIS-GCP-189
		bucketIAMPublicWrite{},     // AEGIS-GCP-190
		bqDatasetAdminGrant{},      // AEGIS-GCP-191
		bqTableIAMPublic{},         // AEGIS-GCP-192
		bqTableNoDelProtect{},      // AEGIS-GCP-193
		bqDatasetDataOwnerGrant{},  // AEGIS-GCP-194
		runImageLatestTag{},        // AEGIS-GCP-196
		runNoVPCAccess{},           // AEGIS-GCP-197
		runNoBinaryAuthz{},         // AEGIS-GCP-198
		runGen1ExecEnv{},           // AEGIS-GCP-199
		functionsEOLRuntime{},      // AEGIS-GCP-200
		functionsNoVPCConnector{},  // AEGIS-GCP-201
		functionsGen1Resource{},    // AEGIS-GCP-202
		runDefaultComputeSAExp{},   // AEGIS-GCP-203
		pubsubNoStoragePolicy{},    // AEGIS-GCP-204
		pubsubSubIAMPublic{},       // AEGIS-GCP-205
		pubsubNoRetainAcked{},      // AEGIS-GCP-206
		pubsubShortRetention{},     // AEGIS-GCP-207
		pubsubNoSchema{},           // AEGIS-GCP-208
		pubsubNoRetryPolicy{},      // AEGIS-GCP-209
		backendNoHealthCheck{},     // AEGIS-GCP-210
		backendNoIAP{},             // AEGIS-GCP-211
		sslCompatibleProfile{},     // AEGIS-GCP-212
		backendPlainHTTP{},         // AEGIS-GCP-213
		fwAllPortsNoPortsList{},    // AEGIS-GCP-214
		fwNoDescription{},          // AEGIS-GCP-215
		subnetExternalIPv6{},       // AEGIS-GCP-216
		subnetNoPGAUnset{},         // AEGIS-GCP-217
		routerNATNoLogging{},       // AEGIS-GCP-218
		sslWeakCustomCiphers{},     // AEGIS-GCP-219
		targetPoolNoHealthCheck{},  // AEGIS-GCP-220
		networkAutoSubnetworks{},   // AEGIS-GCP-221
		fwLoggingNoMetadata{},      // AEGIS-GCP-222
	}
}

// publicMemberInList scans a members-style list value for allUsers /
// allAuthenticatedUsers. It reports undecided=true when the value is
// unresolved or not a string list (caller must return nil).
func publicMemberInList(v ir.Value) (found, undecided bool) {
	if !v.Known {
		return false, true
	}
	l, ok := v.AsList()
	if !ok {
		return false, true
	}
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return false, true
		}
		if isPublicMember(s) {
			return true, false
		}
	}
	return false, false
}

// parseDurationSecs parses a GCP duration string like "3600s" into seconds.
func parseDurationSecs(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "s") || len(s) < 2 {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
	if err != nil || f < 0 {
		return 0, false
	}
	return f, true
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-183: GCS bucket without soft-delete protection
// ---------------------------------------------------------------------------

type bucketNoSoftDelete struct{}

func (bucketNoSoftDelete) ID() string { return "AEGIS-GCP-183" }
func (bucketNoSoftDelete) Title() string {
	return "GCS bucket without soft-delete protection"
}
func (bucketNoSoftDelete) Description() string {
	return "google_storage_bucket with no soft_delete_policy block loses " +
		"the safety net that retains deleted objects for recovery. " +
		"Configure soft_delete_policy to guard against accidental or " +
		"malicious deletion."
}
func (bucketNoSoftDelete) Severity() ir.Severity { return ir.SeverityLow }

func (bucketNoSoftDelete) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket"
}

func (s bucketNoSoftDelete) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "soft_delete_policy")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "soft_delete_policy",
		evidenceSpan(span, r.Span), "absent",
		"soft_delete_policy { retention_duration_seconds = 604800 }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-184: GCS bucket with versioning but no lifecycle management
// ---------------------------------------------------------------------------

type bucketVersioningNoLife struct{}

func (bucketVersioningNoLife) ID() string { return "AEGIS-GCP-184" }
func (bucketVersioningNoLife) Title() string {
	return "GCS bucket with versioning but no lifecycle rule"
}
func (bucketVersioningNoLife) Description() string {
	return "google_storage_bucket with versioning.enabled = true but no " +
		"lifecycle_rule accumulates noncurrent versions indefinitely, " +
		"growing cost and stale-data exposure. Add a lifecycle rule to " +
		"expire old versions."
}
func (bucketVersioningNoLife) Severity() ir.Severity { return ir.SeverityLow }

func (bucketVersioningNoLife) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket"
}

func (s bucketVersioningNoLife) Check(r ir.Resource) []ir.Finding {
	vblks, _, vpresent, vknown := getBlocks(r, "versioning")
	if !vpresent || !vknown {
		return nil
	}
	enabled := false
	for _, b := range vblks {
		en, _, _, kok := blockBool(b, "enabled")
		if !kok {
			return nil // unresolved: cannot decide
		}
		if en {
			enabled = true
		}
	}
	if !enabled {
		return nil
	}
	_, span, lpresent, lknown := getBlocks(r, "lifecycle_rule")
	if lpresent && !lknown {
		return nil
	}
	if lpresent {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "lifecycle_rule",
		evidenceSpan(span, r.Span),
		"absent with versioning enabled",
		"lifecycle_rule { action { type = \"Delete\" } condition { num_newer_versions = 3 } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-185: GCS bucket IAM policy with public binding
// ---------------------------------------------------------------------------

type bucketIAMPolicyPublic struct{}

func (bucketIAMPolicyPublic) ID() string { return "AEGIS-GCP-185" }
func (bucketIAMPolicyPublic) Title() string {
	return "GCS bucket IAM policy with public binding"
}
func (bucketIAMPolicyPublic) Description() string {
	return "google_storage_bucket_iam_policy is authoritative: a binding " +
		"granting a broad storage role to allUsers or " +
		"allAuthenticatedUsers exposes the bucket to the internet, and " +
		"replaces (not merges) any existing policy."
}
func (bucketIAMPolicyPublic) Severity() ir.Severity { return ir.SeverityCritical }

func (bucketIAMPolicyPublic) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket_iam_policy"
}

func (s bucketIAMPolicyPublic) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "bindings")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		role, _, rp, rk := blockString(b, "role")
		if rp && !rk {
			return nil // unresolved: cannot decide
		}
		if !rp || !isBroadReadRole(role) {
			continue
		}
		mv, mok := b["members"]
		if !mok {
			continue
		}
		found, undecided := publicMemberInList(mv)
		if undecided {
			return nil
		}
		if found {
			return []ir.Finding{mkFinding(s, r, "bindings",
				evidenceSpan(span, r.Span),
				"public members with role "+role,
				"remove allUsers/allAuthenticatedUsers from the policy")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-186: GCS default object ACL grants public access
// ---------------------------------------------------------------------------

type bucketDefObjACLPublic struct{}

func (bucketDefObjACLPublic) ID() string { return "AEGIS-GCP-186" }
func (bucketDefObjACLPublic) Title() string {
	return "GCS default object ACL grants public access"
}
func (bucketDefObjACLPublic) Description() string {
	return "google_storage_default_object_access_control (or " +
		"google_storage_object_access_control) with entity allUsers or " +
		"allAuthenticatedUsers makes new (or specific) objects readable " +
		"by the internet by default."
}
func (bucketDefObjACLPublic) Severity() ir.Severity { return ir.SeverityCritical }

func (bucketDefObjACLPublic) AppliesTo(resType string) bool {
	return resType == "google_storage_default_object_access_control" ||
		resType == "google_storage_object_access_control"
}

func (s bucketDefObjACLPublic) Check(r ir.Resource) []ir.Finding {
	entity, span, present, known := getString(r, "entity")
	if !present || !known {
		return nil
	}
	if isPublicMember(entity) {
		return []ir.Finding{mkFinding(s, r, "entity", span, entity,
			"entity restricted to specific users/groups/service accounts")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-187: GCS bucket retention policy not locked
// ---------------------------------------------------------------------------

type bucketRetentionUnlocked struct{}

func (bucketRetentionUnlocked) ID() string { return "AEGIS-GCP-187" }
func (bucketRetentionUnlocked) Title() string {
	return "GCS bucket retention policy not locked"
}
func (bucketRetentionUnlocked) Description() string {
	return "google_storage_bucket with a retention_policy whose is_locked " +
		"is not true lets anyone with storage admin reduce or remove the " +
		"retention period, defeating WORM compliance. Lock the retention " +
		"policy once the period is finalized."
}
func (bucketRetentionUnlocked) Severity() ir.Severity { return ir.SeverityLow }

func (bucketRetentionUnlocked) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket"
}

func (s bucketRetentionUnlocked) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "retention_policy")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		locked, _, lpresent, lknown := blockBool(b, "is_locked")
		if lpresent && !lknown {
			return nil // unresolved: cannot decide
		}
		if lpresent && locked {
			return nil
		}
		actual := "false"
		if !lpresent {
			actual = "absent (provider default: false)"
		}
		return []ir.Finding{mkFinding(s, r, "retention_policy.is_locked",
			evidenceSpan(span, r.Span), actual,
			"retention_policy { is_locked = true }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-188: GCS bucket IAM admin granted to an entire domain
// ---------------------------------------------------------------------------

type bucketIAMDomainAdmin struct{}

func (bucketIAMDomainAdmin) ID() string { return "AEGIS-GCP-188" }
func (bucketIAMDomainAdmin) Title() string {
	return "GCS bucket IAM admin granted to an entire domain"
}
func (bucketIAMDomainAdmin) Description() string {
	return "A bucket IAM binding/member granting a storage admin role to " +
		"domain:<domain> gives every account in that domain full control " +
		"of the bucket. Scope admin grants to named groups or service " +
		"accounts."
}
func (bucketIAMDomainAdmin) Severity() ir.Severity { return ir.SeverityHigh }

func (bucketIAMDomainAdmin) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket_iam_binding" ||
		resType == "google_storage_bucket_iam_member"
}

func isDomainMember(m string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(m)), "domain:")
}

func isAdminRole(role string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(role)), "admin")
}

func (s bucketIAMDomainAdmin) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil
	}
	if !isAdminRole(role) {
		return nil
	}
	check := func(m, attr string, span ir.Span) []ir.Finding {
		if isDomainMember(m) {
			return []ir.Finding{mkFinding(s, r, attr, span,
				m+" with role "+role,
				"grant admin to a named group or service account")}
		}
		return nil
	}
	if r.Type == "google_storage_bucket_iam_binding" {
		mv, mok := r.Attributes["members"]
		if !mok || !mv.Known {
			return nil
		}
		l, ok := mv.AsList()
		if !ok {
			return nil
		}
		for _, item := range l {
			m, ok := item.AsString()
			if !ok {
				return nil
			}
			if f := check(m, "members", evidenceSpan(item.Span, r.Span)); f != nil {
				return f
			}
		}
		return nil
	}
	member, span, present, known := getString(r, "member")
	if !present || !known {
		return nil
	}
	return check(member, "member", span)
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-189: GCS bucket CORS allows insecure HTTP origin
// ---------------------------------------------------------------------------

type bucketCORSInsecureOrigin struct{}

func (bucketCORSInsecureOrigin) ID() string { return "AEGIS-GCP-189" }
func (bucketCORSInsecureOrigin) Title() string {
	return "GCS bucket CORS allows insecure HTTP origin"
}
func (bucketCORSInsecureOrigin) Description() string {
	return "google_storage_bucket cors block with an http:// (non-TLS) " +
		"origin lets pages served over plaintext HTTP read bucket " +
		"objects cross-origin, exposing traffic to interception. Allow " +
		"only https:// origins."
}
func (bucketCORSInsecureOrigin) Severity() ir.Severity { return ir.SeverityMedium }

func (bucketCORSInsecureOrigin) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket"
}

func (s bucketCORSInsecureOrigin) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "cors")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		ov, ook := b["origin"]
		if !ook {
			continue
		}
		if !ov.Known {
			return nil
		}
		l, ok := ov.AsList()
		if !ok {
			return nil
		}
		for _, item := range l {
			o, ok := item.AsString()
			if !ok {
				return nil
			}
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(o)), "http://") {
				return []ir.Finding{mkFinding(s, r, "cors.origin", item.Span,
					o, "https:// origins only")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-190: GCS bucket publicly writable via IAM
// ---------------------------------------------------------------------------

type bucketIAMPublicWrite struct{}

func (bucketIAMPublicWrite) ID() string { return "AEGIS-GCP-190" }
func (bucketIAMPublicWrite) Title() string {
	return "GCS bucket publicly writable via IAM"
}
func (bucketIAMPublicWrite) Description() string {
	return "A bucket IAM binding/member granting roles/storage.objectCreator " +
		"(or another write-only role) to allUsers or " +
		"allAuthenticatedUsers lets anyone on the internet write objects " +
		"into the bucket, enabling abuse and content injection."
}
func (bucketIAMPublicWrite) Severity() ir.Severity { return ir.SeverityCritical }

func (bucketIAMPublicWrite) AppliesTo(resType string) bool {
	return resType == "google_storage_bucket_iam_binding" ||
		resType == "google_storage_bucket_iam_member"
}

func (s bucketIAMPublicWrite) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(role)), "objectcreator") {
		return nil
	}
	if r.Type == "google_storage_bucket_iam_binding" {
		mv, mok := r.Attributes["members"]
		if !mok {
			return nil
		}
		found, undecided := publicMemberInList(mv)
		if undecided {
			return nil
		}
		if found {
			return []ir.Finding{mkFinding(s, r, "members", mv.Span,
				"allUsers/allAuthenticatedUsers with "+role,
				"remove public members from the binding")}
		}
		return nil
	}
	member, span, present, known := getString(r, "member")
	if !present || !known {
		return nil
	}
	if isPublicMember(member) {
		return []ir.Finding{mkFinding(s, r, "member", span,
			member+" with "+role, "remove public members")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-191: BigQuery dataset grants bigquery.admin
// ---------------------------------------------------------------------------

type bqDatasetAdminGrant struct{}

func (bqDatasetAdminGrant) ID() string { return "AEGIS-GCP-191" }
func (bqDatasetAdminGrant) Title() string {
	return "BigQuery dataset grants bigquery.admin"
}
func (bqDatasetAdminGrant) Description() string {
	return "google_bigquery_dataset access entry with a role containing " +
		"bigquery.admin grants full control of the dataset, including " +
		"sharing and deletion. Use granular dataViewer/dataEditor roles " +
		"instead."
}
func (bqDatasetAdminGrant) Severity() ir.Severity { return ir.SeverityHigh }

func (bqDatasetAdminGrant) AppliesTo(resType string) bool {
	return resType == "google_bigquery_dataset"
}

func (s bqDatasetAdminGrant) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "access")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		role, span, rp, rk := blockString(b, "role")
		if rp && !rk {
			return nil
		}
		if !rp {
			continue
		}
		if strings.Contains(strings.ToLower(strings.TrimSpace(role)), "bigquery.admin") {
			return []ir.Finding{mkFinding(s, r, "access.role", span, role,
				"granular roles/bigquery.dataViewer or dataEditor")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-192: BigQuery table IAM grants data access to the public
// ---------------------------------------------------------------------------

type bqTableIAMPublic struct{}

func (bqTableIAMPublic) ID() string { return "AEGIS-GCP-192" }
func (bqTableIAMPublic) Title() string {
	return "BigQuery table IAM grants data access to the public"
}
func (bqTableIAMPublic) Description() string {
	return "google_bigquery_table_iam_binding/member granting " +
		"roles/bigquery.dataViewer (or editor/admin) to allUsers or " +
		"allAuthenticatedUsers exposes table data to the internet."
}
func (bqTableIAMPublic) Severity() ir.Severity { return ir.SeverityCritical }

func (bqTableIAMPublic) AppliesTo(resType string) bool {
	return resType == "google_bigquery_table_iam_binding" ||
		resType == "google_bigquery_table_iam_member"
}

func isBQDataRole(role string) bool {
	lr := strings.ToLower(strings.TrimSpace(role))
	return strings.Contains(lr, "dataviewer") ||
		strings.Contains(lr, "dataeditor") ||
		strings.Contains(lr, "dataowner") ||
		strings.Contains(lr, "admin")
}

func (s bqTableIAMPublic) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil
	}
	if !isBQDataRole(role) {
		return nil
	}
	if r.Type == "google_bigquery_table_iam_binding" {
		mv, mok := r.Attributes["members"]
		if !mok {
			return nil
		}
		found, undecided := publicMemberInList(mv)
		if undecided {
			return nil
		}
		if found {
			return []ir.Finding{mkFinding(s, r, "members", mv.Span,
				"allUsers/allAuthenticatedUsers with "+role,
				"remove public members")}
		}
		return nil
	}
	member, span, present, known := getString(r, "member")
	if !present || !known {
		return nil
	}
	if isPublicMember(member) {
		return []ir.Finding{mkFinding(s, r, "member", span,
			member+" with "+role, "remove public members")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-193: BigQuery table without deletion protection
// ---------------------------------------------------------------------------

type bqTableNoDelProtect struct{}

func (bqTableNoDelProtect) ID() string { return "AEGIS-GCP-193" }
func (bqTableNoDelProtect) Title() string {
	return "BigQuery table without deletion protection"
}
func (bqTableNoDelProtect) Description() string {
	return "google_bigquery_table with deletion_protection = false can be " +
		"dropped by an errant apply or compromised credential. Enable " +
		"deletion protection for tables that must survive."
}
func (bqTableNoDelProtect) Severity() ir.Severity { return ir.SeverityLow }

func (bqTableNoDelProtect) AppliesTo(resType string) bool {
	return resType == "google_bigquery_table"
}

func (s bqTableNoDelProtect) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "deletion_protection")
	if !present || !known {
		return nil // only an explicit false fires
	}
	if en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "deletion_protection", span,
		"false", "deletion_protection = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-194: BigQuery dataset grants dataOwner
// ---------------------------------------------------------------------------

type bqDatasetDataOwnerGrant struct{}

func (bqDatasetDataOwnerGrant) ID() string { return "AEGIS-GCP-194" }
func (bqDatasetDataOwnerGrant) Title() string {
	return "BigQuery dataset grants dataOwner"
}
func (bqDatasetDataOwnerGrant) Description() string {
	return "google_bigquery_dataset access entry with a role containing " +
		"dataOwner can update, share, and delete the dataset and its " +
		"tables. Reserve dataOwner for break-glass identities and use " +
		"dataEditor for writers."
}
func (bqDatasetDataOwnerGrant) Severity() ir.Severity { return ir.SeverityHigh }

func (bqDatasetDataOwnerGrant) AppliesTo(resType string) bool {
	return resType == "google_bigquery_dataset"
}

func (s bqDatasetDataOwnerGrant) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "access")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		role, span, rp, rk := blockString(b, "role")
		if rp && !rk {
			return nil
		}
		if !rp {
			continue
		}
		if strings.Contains(strings.ToLower(strings.TrimSpace(role)), "dataowner") {
			return []ir.Finding{mkFinding(s, r, "access.role", span, role,
				"roles/bigquery.dataEditor for writers")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-196: Cloud Run service image uses mutable tag
// ---------------------------------------------------------------------------

type runImageLatestTag struct{}

func (runImageLatestTag) ID() string { return "AEGIS-GCP-196" }
func (runImageLatestTag) Title() string {
	return "Cloud Run service image uses mutable tag"
}
func (runImageLatestTag) Description() string {
	return "google_cloud_run_v2_service container image with the :latest " +
		"tag (or no tag) is mutable: redeploys can silently change what " +
		"runs and break image-digest pinning. Pin an immutable tag or " +
		"digest."
}
func (runImageLatestTag) Severity() ir.Severity { return ir.SeverityLow }

func (runImageLatestTag) AppliesTo(resType string) bool {
	return resType == "google_cloud_run_v2_service"
}

// imageTagMutable reports whether an image reference uses :latest or no tag.
func imageTagMutable(img string) bool {
	ref := img
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i] // digest-pinned: tag irrelevant
		return false
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return true // no tag at all
	}
	tag := ref[i+1:]
	if strings.Contains(tag, "/") {
		return true // colon was a registry port, no tag present
	}
	return strings.EqualFold(tag, "latest")
}

func (s runImageLatestTag) Check(r ir.Resource) []ir.Finding {
	tblks, _, present, known := getBlocks(r, "template")
	if !present || !known {
		return nil
	}
	for _, t := range tblks {
		for _, c := range blockList(t, "containers") {
			img, span, ip, ik := blockString(c, "image")
			if ip && !ik {
				return nil
			}
			if !ip {
				continue
			}
			if imageTagMutable(img) {
				return []ir.Finding{mkFinding(s, r,
					"template.containers.image", span, img,
					"image = \"<registry>/<repo>:<immutable-tag>\" or digest")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-197: Cloud Run service without VPC access
// ---------------------------------------------------------------------------

type runNoVPCAccess struct{}

func (runNoVPCAccess) ID() string { return "AEGIS-GCP-197" }
func (runNoVPCAccess) Title() string {
	return "Cloud Run service without VPC access"
}
func (runNoVPCAccess) Description() string {
	return "google_cloud_run_v2_service template with no vpc_access block " +
		"cannot reach private VPC resources, pushing traffic over public " +
		"paths. Attach a VPC connector for private egress."
}
func (runNoVPCAccess) Severity() ir.Severity { return ir.SeverityLow }

func (runNoVPCAccess) AppliesTo(resType string) bool {
	return resType == "google_cloud_run_v2_service"
}

func (s runNoVPCAccess) Check(r ir.Resource) []ir.Finding {
	tblks, span, present, known := getBlocks(r, "template")
	if !present || !known {
		return nil
	}
	for _, t := range tblks {
		if v, ok := t["vpc_access"]; ok {
			if !v.Known {
				return nil
			}
			return nil // present: explicitly configured
		}
		return []ir.Finding{mkFinding(s, r, "template.vpc_access",
			evidenceSpan(span, r.Span), "absent",
			"template { vpc_access { connector = \"...\" egress = \"PRIVATE_RANGES_ONLY\" } }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-198: Cloud Run service without binary authorization
// ---------------------------------------------------------------------------

type runNoBinaryAuthz struct{}

func (runNoBinaryAuthz) ID() string { return "AEGIS-GCP-198" }
func (runNoBinaryAuthz) Title() string {
	return "Cloud Run service without binary authorization"
}
func (runNoBinaryAuthz) Description() string {
	return "google_cloud_run_v2_service with no binary_authorization " +
		"block deploys container images without signature verification. " +
		"Enable binary authorization to enforce deploy-time policy."
}
func (runNoBinaryAuthz) Severity() ir.Severity { return ir.SeverityLow }

func (runNoBinaryAuthz) AppliesTo(resType string) bool {
	return resType == "google_cloud_run_v2_service"
}

func (s runNoBinaryAuthz) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "binary_authorization")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "binary_authorization",
		evidenceSpan(span, r.Span), "absent",
		"binary_authorization { }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-199: Cloud Run service on first-generation execution environment
// ---------------------------------------------------------------------------

type runGen1ExecEnv struct{}

func (runGen1ExecEnv) ID() string { return "AEGIS-GCP-199" }
func (runGen1ExecEnv) Title() string {
	return "Cloud Run service on first-generation execution environment"
}
func (runGen1ExecEnv) Description() string {
	return "google_cloud_run_v2_service template with execution_environment " +
		"= \"EXECUTION_ENVIRONMENT_GEN1\" runs on the older sandbox with a " +
		"weaker isolation boundary. Use the second-generation execution " +
		"environment."
}
func (runGen1ExecEnv) Severity() ir.Severity { return ir.SeverityLow }

func (runGen1ExecEnv) AppliesTo(resType string) bool {
	return resType == "google_cloud_run_v2_service"
}

func (s runGen1ExecEnv) Check(r ir.Resource) []ir.Finding {
	tblks, _, present, known := getBlocks(r, "template")
	if !present || !known {
		return nil
	}
	for _, t := range tblks {
		ee, span, ep, ek := blockString(t, "execution_environment")
		if ep && !ek {
			return nil
		}
		if ep && strings.EqualFold(strings.TrimSpace(ee), "EXECUTION_ENVIRONMENT_GEN1") {
			return []ir.Finding{mkFinding(s, r,
				"template.execution_environment", span, ee,
				"execution_environment = \"EXECUTION_ENVIRONMENT_GEN2\"")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-200: Cloud Function on end-of-life runtime
// ---------------------------------------------------------------------------

type functionsEOLRuntime struct{}

func (functionsEOLRuntime) ID() string { return "AEGIS-GCP-200" }
func (functionsEOLRuntime) Title() string {
	return "Cloud Function on end-of-life runtime"
}
func (functionsEOLRuntime) Description() string {
	return "Cloud Function (1st or 2nd gen) pinned to an end-of-life " +
		"runtime no longer receives security patches. Migrate to a " +
		"supported runtime."
}
func (functionsEOLRuntime) Severity() ir.Severity { return ir.SeverityHigh }

func (functionsEOLRuntime) AppliesTo(resType string) bool {
	return resType == "google_cloudfunctions_function" ||
		resType == "google_cloudfunctions2_function"
}

// eolRuntimes are Cloud Functions runtimes past end of life.
var eolRuntimes = map[string]bool{
	"nodejs16": true, "nodejs18": true,
	"python38": true, "python39": true,
	"java11": true,
	"go119":  true, "go120": true, "go121": true,
	"dotnet6": true,
	"ruby30":  true, "ruby31": true,
	"php81": true, "php82": true,
}

func (s functionsEOLRuntime) Check(r ir.Resource) []ir.Finding {
	var rt string
	var span ir.Span
	var present, known bool
	if r.Type == "google_cloudfunctions2_function" {
		blks, _, bp, bk := getBlocks(r, "build_config")
		if !bp || !bk {
			return nil
		}
		found := false
		for _, b := range blks {
			var p, k bool
			rt, span, p, k = blockString(b, "runtime")
			if p && !k {
				return nil
			}
			if p {
				found = true
				break
			}
		}
		present, known = found, true
	} else {
		rt, span, present, known = getString(r, "runtime")
	}
	if !present || !known {
		return nil
	}
	if eolRuntimes[strings.ToLower(strings.TrimSpace(rt))] {
		return []ir.Finding{mkFinding(s, r, "runtime", span, rt,
			"migrate to a supported runtime")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-201: Cloud Function (2nd gen) without VPC connector
// ---------------------------------------------------------------------------

type functionsNoVPCConnector struct{}

func (functionsNoVPCConnector) ID() string { return "AEGIS-GCP-201" }
func (functionsNoVPCConnector) Title() string {
	return "Cloud Function (2nd gen) without VPC connector"
}
func (functionsNoVPCConnector) Description() string {
	return "google_cloudfunctions2_function service_config with no " +
		"vpc_connector cannot reach private VPC resources, pushing " +
		"egress over public paths. Attach a VPC connector for private " +
		"egress."
}
func (functionsNoVPCConnector) Severity() ir.Severity { return ir.SeverityLow }

func (functionsNoVPCConnector) AppliesTo(resType string) bool {
	return resType == "google_cloudfunctions2_function"
}

func (s functionsNoVPCConnector) Check(r ir.Resource) []ir.Finding {
	scblks, span, present, known := getBlocks(r, "service_config")
	if !present || !known {
		return nil
	}
	for _, sc := range scblks {
		vc, _, vcp, vck := blockString(sc, "vpc_connector")
		if vcp && !vck {
			return nil
		}
		if vcp && strings.TrimSpace(vc) != "" {
			return nil
		}
		return []ir.Finding{mkFinding(s, r, "service_config.vpc_connector",
			evidenceSpan(span, r.Span), "absent",
			"service_config { vpc_connector = \"...\" vpc_connector_egress_settings = \"PRIVATE_RANGES_ONLY\" }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-202: First-generation Cloud Function
// ---------------------------------------------------------------------------

type functionsGen1Resource struct{}

func (functionsGen1Resource) ID() string { return "AEGIS-GCP-202" }
func (functionsGen1Resource) Title() string {
	return "First-generation Cloud Function"
}
func (functionsGen1Resource) Description() string {
	return "google_cloudfunctions_function is the 1st-gen runtime with an " +
		"older security model (no VPC connector egress controls, weaker " +
		"concurrency isolation). Migrate to " +
		"google_cloudfunctions2_function."
}
func (functionsGen1Resource) Severity() ir.Severity { return ir.SeverityLow }

func (functionsGen1Resource) AppliesTo(resType string) bool {
	return resType == "google_cloudfunctions_function"
}

func (s functionsGen1Resource) Check(r ir.Resource) []ir.Finding {
	return []ir.Finding{mkFinding(s, r, "runtime",
		evidenceSpan(ir.Span{}, r.Span),
		"1st-gen function resource",
		"migrate to google_cloudfunctions2_function")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-203: Cloud Run service with explicit default compute SA
// ---------------------------------------------------------------------------

type runDefaultComputeSAExp struct{}

func (runDefaultComputeSAExp) ID() string { return "AEGIS-GCP-203" }
func (runDefaultComputeSAExp) Title() string {
	return "Cloud Run service with explicit default compute service account"
}
func (runDefaultComputeSAExp) Description() string {
	return "google_cloud_run_v2_service template.service_account " +
		"explicitly set to the default Compute Engine service account " +
		"(...compute@developer.gserviceaccount.com) grants the service " +
		"broad project permissions. Use a dedicated least-privilege " +
		"service account."
}
func (runDefaultComputeSAExp) Severity() ir.Severity { return ir.SeverityMedium }

func (runDefaultComputeSAExp) AppliesTo(resType string) bool {
	return resType == "google_cloud_run_v2_service"
}

func (s runDefaultComputeSAExp) Check(r ir.Resource) []ir.Finding {
	tblks, _, present, known := getBlocks(r, "template")
	if !present || !known {
		return nil
	}
	for _, t := range tblks {
		sa, span, sp, sk := blockString(t, "service_account")
		if sp && !sk {
			return nil
		}
		if sp && strings.Contains(sa, "compute@developer.gserviceaccount.com") {
			return []ir.Finding{mkFinding(s, r,
				"template.service_account", span, sa,
				"service_account = \"<dedicated-sa>@<project>.iam.gserviceaccount.com\"")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-204: Pub/Sub topic without message storage policy
// ---------------------------------------------------------------------------

type pubsubNoStoragePolicy struct{}

func (pubsubNoStoragePolicy) ID() string { return "AEGIS-GCP-204" }
func (pubsubNoStoragePolicy) Title() string {
	return "Pub/Sub topic without message storage policy"
}
func (pubsubNoStoragePolicy) Description() string {
	return "google_pubsub_topic with no message_storage_policy lets " +
		"Google store message data in any region, which can violate data " +
		"residency requirements. Pin allowed_persistence_regions."
}
func (pubsubNoStoragePolicy) Severity() ir.Severity { return ir.SeverityLow }

func (pubsubNoStoragePolicy) AppliesTo(resType string) bool {
	return resType == "google_pubsub_topic"
}

func (s pubsubNoStoragePolicy) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "message_storage_policy")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "message_storage_policy",
		evidenceSpan(span, r.Span), "absent (any region)",
		"message_storage_policy { allowed_persistence_regions = [\"<region>\"] }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-205: Pub/Sub subscription IAM grants to the public
// ---------------------------------------------------------------------------

type pubsubSubIAMPublic struct{}

func (pubsubSubIAMPublic) ID() string { return "AEGIS-GCP-205" }
func (pubsubSubIAMPublic) Title() string {
	return "Pub/Sub subscription IAM grants to the public"
}
func (pubsubSubIAMPublic) Description() string {
	return "google_pubsub_subscription_iam_binding/member granting " +
		"roles/pubsub.subscriber (or viewer/admin) to allUsers or " +
		"allAuthenticatedUsers lets the internet pull messages from the " +
		"subscription."
}
func (pubsubSubIAMPublic) Severity() ir.Severity { return ir.SeverityCritical }

func (pubsubSubIAMPublic) AppliesTo(resType string) bool {
	return resType == "google_pubsub_subscription_iam_binding" ||
		resType == "google_pubsub_subscription_iam_member"
}

func isPubSubDataRole(role string) bool {
	lr := strings.ToLower(strings.TrimSpace(role))
	return strings.Contains(lr, "subscriber") ||
		strings.Contains(lr, "viewer") ||
		strings.Contains(lr, "admin")
}

func (s pubsubSubIAMPublic) Check(r ir.Resource) []ir.Finding {
	role, _, present, known := getString(r, "role")
	if !present || !known {
		return nil
	}
	if !isPubSubDataRole(role) {
		return nil
	}
	if r.Type == "google_pubsub_subscription_iam_binding" {
		mv, mok := r.Attributes["members"]
		if !mok {
			return nil
		}
		found, undecided := publicMemberInList(mv)
		if undecided {
			return nil
		}
		if found {
			return []ir.Finding{mkFinding(s, r, "members", mv.Span,
				"allUsers/allAuthenticatedUsers with "+role,
				"remove public members")}
		}
		return nil
	}
	member, span, present, known := getString(r, "member")
	if !present || !known {
		return nil
	}
	if isPublicMember(member) {
		return []ir.Finding{mkFinding(s, r, "member", span,
			member+" with "+role, "remove public members")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-206: Pub/Sub subscription does not retain acked messages
// ---------------------------------------------------------------------------

type pubsubNoRetainAcked struct{}

func (pubsubNoRetainAcked) ID() string { return "AEGIS-GCP-206" }
func (pubsubNoRetainAcked) Title() string {
	return "Pub/Sub subscription does not retain acked messages"
}
func (pubsubNoRetainAcked) Description() string {
	return "google_pubsub_subscription with retain_acked_messages = false " +
		"discards acknowledged messages immediately, removing the " +
		"ability to replay them for incident investigation. Retain acked " +
		"messages when the subscription backs an audit trail."
}
func (pubsubNoRetainAcked) Severity() ir.Severity { return ir.SeverityLow }

func (pubsubNoRetainAcked) AppliesTo(resType string) bool {
	return resType == "google_pubsub_subscription"
}

func (s pubsubNoRetainAcked) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "retain_acked_messages")
	if !present || !known {
		return nil // only an explicit false fires
	}
	if en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "retain_acked_messages", span,
		"false", "retain_acked_messages = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-207: Pub/Sub topic message retention under 7 days
// ---------------------------------------------------------------------------

type pubsubShortRetention struct{}

func (pubsubShortRetention) ID() string { return "AEGIS-GCP-207" }
func (pubsubShortRetention) Title() string {
	return "Pub/Sub topic message retention under 7 days"
}
func (pubsubShortRetention) Description() string {
	return "google_pubsub_topic with message_retention_duration below 7 " +
		"days limits the window for replaying messages during incident " +
		"response. Keep at least 7 days of retention."
}
func (pubsubShortRetention) Severity() ir.Severity { return ir.SeverityLow }

func (pubsubShortRetention) AppliesTo(resType string) bool {
	return resType == "google_pubsub_topic"
}

func (s pubsubShortRetention) Check(r ir.Resource) []ir.Finding {
	dur, span, present, known := getString(r, "message_retention_duration")
	if !present || !known {
		return nil
	}
	secs, ok := parseDurationSecs(dur)
	if !ok {
		return nil // unparseable: cannot decide
	}
	if secs >= 604800 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "message_retention_duration", span,
		dur, "message_retention_duration = \"604800s\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-208: Pub/Sub topic without schema validation
// ---------------------------------------------------------------------------

type pubsubNoSchema struct{}

func (pubsubNoSchema) ID() string { return "AEGIS-GCP-208" }
func (pubsubNoSchema) Title() string {
	return "Pub/Sub topic without schema validation"
}
func (pubsubNoSchema) Description() string {
	return "google_pubsub_topic with no schema_settings block accepts " +
		"arbitrary message payloads, letting malformed or malicious " +
		"messages reach subscribers. Attach a schema for validation."
}
func (pubsubNoSchema) Severity() ir.Severity { return ir.SeverityLow }

func (pubsubNoSchema) AppliesTo(resType string) bool {
	return resType == "google_pubsub_topic"
}

func (s pubsubNoSchema) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "schema_settings")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "schema_settings",
		evidenceSpan(span, r.Span), "absent",
		"schema_settings { schema = \"...\" encoding = \"JSON\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-209: Pub/Sub subscription without retry policy
// ---------------------------------------------------------------------------

type pubsubNoRetryPolicy struct{}

func (pubsubNoRetryPolicy) ID() string { return "AEGIS-GCP-209" }
func (pubsubNoRetryPolicy) Title() string {
	return "Pub/Sub subscription without retry policy"
}
func (pubsubNoRetryPolicy) Description() string {
	return "google_pubsub_subscription with no retry_policy block falls " +
		"back to immediate redelivery, which can hammer a struggling " +
		"subscriber. Configure a retry policy with backoff."
}
func (pubsubNoRetryPolicy) Severity() ir.Severity { return ir.SeverityLow }

func (pubsubNoRetryPolicy) AppliesTo(resType string) bool {
	return resType == "google_pubsub_subscription"
}

func (s pubsubNoRetryPolicy) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "retry_policy")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "retry_policy",
		evidenceSpan(span, r.Span), "absent",
		"retry_policy { minimum_backoff = \"10s\" maximum_backoff = \"600s\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-210: Backend service without health checks
// ---------------------------------------------------------------------------

type backendNoHealthCheck struct{}

func (backendNoHealthCheck) ID() string { return "AEGIS-GCP-210" }
func (backendNoHealthCheck) Title() string {
	return "Backend service without health checks"
}
func (backendNoHealthCheck) Description() string {
	return "google_compute_backend_service with no health_checks sends " +
		"traffic to backends without verifying they are healthy, and " +
		"misses the signal when a backend is compromised or failing. " +
		"Attach a health check."
}
func (backendNoHealthCheck) Severity() ir.Severity { return ir.SeverityMedium }

func (backendNoHealthCheck) AppliesTo(resType string) bool {
	return resType == "google_compute_backend_service"
}

// healthChecksEmpty reports whether a health_checks-style attribute is
// absent or an empty list; undecided when unresolved.
func healthChecksEmpty(r ir.Resource, name string) (empty, undecided bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return true, false
	}
	if !v.Known {
		return false, true
	}
	l, ok := v.AsList()
	if !ok {
		return false, true
	}
	return len(l) == 0, false
}

func (s backendNoHealthCheck) Check(r ir.Resource) []ir.Finding {
	empty, undecided := healthChecksEmpty(r, "health_checks")
	if undecided {
		return nil
	}
	if !empty {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "health_checks",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"health_checks = [google_compute_health_check.example.id]")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-211: Backend service without Identity-Aware Proxy
// ---------------------------------------------------------------------------

type backendNoIAP struct{}

func (backendNoIAP) ID() string { return "AEGIS-GCP-211" }
func (backendNoIAP) Title() string {
	return "Backend service without Identity-Aware Proxy"
}
func (backendNoIAP) Description() string {
	return "google_compute_backend_service with no iap block exposes the " +
		"backend without Google's identity-aware access control. Enable " +
		"IAP to require authentication before traffic reaches backends."
}
func (backendNoIAP) Severity() ir.Severity { return ir.SeverityMedium }

func (backendNoIAP) AppliesTo(resType string) bool {
	return resType == "google_compute_backend_service"
}

func (s backendNoIAP) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "iap")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "iap",
		evidenceSpan(span, r.Span), "absent",
		"iap { oauth2_client_id = \"...\" oauth2_client_secret = \"...\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-212: SSL policy with COMPATIBLE profile
// ---------------------------------------------------------------------------

type sslCompatibleProfile struct{}

func (sslCompatibleProfile) ID() string { return "AEGIS-GCP-212" }
func (sslCompatibleProfile) Title() string {
	return "SSL policy with COMPATIBLE profile"
}
func (sslCompatibleProfile) Description() string {
	return "google_compute_ssl_policy with profile = \"COMPATIBLE\" " +
		"permits TLS 1.0 and broad cipher support for old clients. Use " +
		"the MODERN or RESTRICTED profile, or a CUSTOM profile pinned to " +
		"TLS 1.2+."
}
func (sslCompatibleProfile) Severity() ir.Severity { return ir.SeverityMedium }

func (sslCompatibleProfile) AppliesTo(resType string) bool {
	return resType == "google_compute_ssl_policy"
}

func (s sslCompatibleProfile) Check(r ir.Resource) []ir.Finding {
	prof, span, present, known := getString(r, "profile")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(prof), "COMPATIBLE") {
		return []ir.Finding{mkFinding(s, r, "profile", span, prof,
			"profile = \"MODERN\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-213: Backend service with plaintext HTTP protocol
// ---------------------------------------------------------------------------

type backendPlainHTTP struct{}

func (backendPlainHTTP) ID() string { return "AEGIS-GCP-213" }
func (backendPlainHTTP) Title() string {
	return "Backend service with plaintext HTTP protocol"
}
func (backendPlainHTTP) Description() string {
	return "google_compute_backend_service with protocol = \"HTTP\" sends " +
		"traffic to backends unencrypted. Use HTTPS (or HTTP/2) so " +
		"load-balancer-to-backend traffic is encrypted in transit."
}
func (backendPlainHTTP) Severity() ir.Severity { return ir.SeverityMedium }

func (backendPlainHTTP) AppliesTo(resType string) bool {
	return resType == "google_compute_backend_service"
}

func (s backendPlainHTTP) Check(r ir.Resource) []ir.Finding {
	p, span, present, known := getString(r, "protocol")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(p), "HTTP") {
		return []ir.Finding{mkFinding(s, r, "protocol", span, p,
			"protocol = \"HTTPS\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-214: Firewall allows all ports to the world (ports omitted)
// ---------------------------------------------------------------------------

type fwAllPortsNoPortsList struct{}

func (fwAllPortsNoPortsList) ID() string { return "AEGIS-GCP-214" }
func (fwAllPortsNoPortsList) Title() string {
	return "Firewall allows all ports to the world (ports omitted)"
}
func (fwAllPortsNoPortsList) Description() string {
	return "google_compute_firewall with an allow block for TCP/UDP/ALL " +
		"from 0.0.0.0/0 and no ports list opens every port to the " +
		"internet. Restrict ports to the minimum required."
}
func (fwAllPortsNoPortsList) Severity() ir.Severity { return ir.SeverityHigh }

func (fwAllPortsNoPortsList) AppliesTo(resType string) bool {
	return resType == "google_compute_firewall"
}

func (s fwAllPortsNoPortsList) Check(r ir.Resource) []ir.Finding {
	ranges, _, ok := getStringList(r, "source_ranges")
	if !ok {
		return nil
	}
	world := false
	for _, sr := range ranges {
		if strings.TrimSpace(sr) == "0.0.0.0/0" {
			world = true
			break
		}
	}
	if !world {
		return nil
	}
	blks, span, present, known := getBlocks(r, "allow")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	for _, b := range blks {
		if v, ok := b["ports"]; ok {
			if !v.Known {
				return nil // unresolved: cannot decide
			}
			continue // ports listed: out of scope for this rule
		}
		proto, _, pp, pk := blockString(b, "protocol")
		if pp && !pk {
			return nil
		}
		if pp {
			lp := strings.ToLower(strings.TrimSpace(proto))
			if lp != "tcp" && lp != "udp" && lp != "all" {
				continue
			}
		}
		return []ir.Finding{mkFinding(s, r, "allow",
			evidenceSpan(span, r.Span),
			"allow from 0.0.0.0/0 with no ports (all ports)",
			"allow { protocol = \"tcp\" ports = [\"443\"] }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-215: Firewall rule without description
// ---------------------------------------------------------------------------

type fwNoDescription struct{}

func (fwNoDescription) ID() string { return "AEGIS-GCP-215" }
func (fwNoDescription) Title() string {
	return "Firewall rule without description"
}
func (fwNoDescription) Description() string {
	return "google_compute_firewall with no description is untracked rule " +
		"sprawl: reviewers cannot tell why the rule exists or who owns " +
		"it. Document every firewall rule."
}
func (fwNoDescription) Severity() ir.Severity { return ir.SeverityLow }

func (fwNoDescription) AppliesTo(resType string) bool {
	return resType == "google_compute_firewall"
}

func (s fwNoDescription) Check(r ir.Resource) []ir.Finding {
	d, span, present, known := getString(r, "description")
	if present && !known {
		return nil
	}
	if present && strings.TrimSpace(d) != "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "description",
		evidenceSpan(span, r.Span), "absent",
		"description = \"<owner>: <purpose>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-216: Subnetwork with external IPv6 access
// ---------------------------------------------------------------------------

type subnetExternalIPv6 struct{}

func (subnetExternalIPv6) ID() string { return "AEGIS-GCP-216" }
func (subnetExternalIPv6) Title() string {
	return "Subnetwork with external IPv6 access"
}
func (subnetExternalIPv6) Description() string {
	return "google_compute_subnetwork with ipv6_access_type = " +
		"\"EXTERNAL\" gives VMs globally routable IPv6 addresses, " +
		"bypassing IPv4 NAT boundaries. Use INTERNAL unless external " +
		"IPv6 is required."
}
func (subnetExternalIPv6) Severity() ir.Severity { return ir.SeverityMedium }

func (subnetExternalIPv6) AppliesTo(resType string) bool {
	return resType == "google_compute_subnetwork"
}

func (s subnetExternalIPv6) Check(r ir.Resource) []ir.Finding {
	t, span, present, known := getString(r, "ipv6_access_type")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(t), "EXTERNAL") {
		return []ir.Finding{mkFinding(s, r, "ipv6_access_type", span, t,
			"ipv6_access_type = \"INTERNAL\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-217: Subnetwork without Private Google Access setting
// ---------------------------------------------------------------------------

type subnetNoPGAUnset struct{}

func (subnetNoPGAUnset) ID() string { return "AEGIS-GCP-217" }
func (subnetNoPGAUnset) Title() string {
	return "Subnetwork without Private Google Access setting"
}
func (subnetNoPGAUnset) Description() string {
	return "google_compute_subnetwork with private_ip_google_access " +
		"unset inherits the provider default (false), forcing VMs to " +
		"use public IPs to reach Google APIs. Set " +
		"private_ip_google_access = true for internal-only workloads."
}
func (subnetNoPGAUnset) Severity() ir.Severity { return ir.SeverityMedium }

func (subnetNoPGAUnset) AppliesTo(resType string) bool {
	return resType == "google_compute_subnetwork"
}

func (s subnetNoPGAUnset) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBool(r, "private_ip_google_access")
	if present && !known {
		return nil
	}
	if present {
		return nil // explicit choice (false is covered by AEGIS-GCP-023)
	}
	return []ir.Finding{mkFinding(s, r, "private_ip_google_access",
		evidenceSpan(span, r.Span), "absent (provider default: false)",
		"private_ip_google_access = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-218: Cloud NAT without logging
// ---------------------------------------------------------------------------

type routerNATNoLogging struct{}

func (routerNATNoLogging) ID() string { return "AEGIS-GCP-218" }
func (routerNATNoLogging) Title() string {
	return "Cloud NAT without logging"
}
func (routerNATNoLogging) Description() string {
	return "google_compute_router_nat with no log_config block records " +
		"no NAT translation logs, leaving outbound connection auditing " +
		"blind. Enable NAT logging."
}
func (routerNATNoLogging) Severity() ir.Severity { return ir.SeverityLow }

func (routerNATNoLogging) AppliesTo(resType string) bool {
	return resType == "google_compute_router_nat"
}

func (s routerNATNoLogging) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getBlocks(r, "log_config")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "log_config",
		evidenceSpan(span, r.Span), "absent",
		"log_config { enable = true filter = \"ERRORS_ONLY\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-219: SSL policy with weak custom cipher suites
// ---------------------------------------------------------------------------

type sslWeakCustomCiphers struct{}

func (sslWeakCustomCiphers) ID() string { return "AEGIS-GCP-219" }
func (sslWeakCustomCiphers) Title() string {
	return "SSL policy with weak custom cipher suites"
}
func (sslWeakCustomCiphers) Description() string {
	return "google_compute_ssl_policy with custom_features including " +
		"3DES, RC4, or non-forward-secret TLS_RSA_WITH_* suites permits " +
		"weak cryptography. Remove weak suites from custom_features."
}
func (sslWeakCustomCiphers) Severity() ir.Severity { return ir.SeverityHigh }

func (sslWeakCustomCiphers) AppliesTo(resType string) bool {
	return resType == "google_compute_ssl_policy"
}

func isWeakCipherSuite(suite string) bool {
	u := strings.ToUpper(strings.TrimSpace(suite))
	return strings.Contains(u, "3DES") ||
		strings.Contains(u, "RC4") ||
		strings.HasPrefix(u, "TLS_RSA_WITH_")
}

func (s sslWeakCustomCiphers) Check(r ir.Resource) []ir.Finding {
	feats, span, ok := getStringList(r, "custom_features")
	if !ok {
		return nil // absent or unresolved: cannot decide
	}
	for _, f := range feats {
		if isWeakCipherSuite(f) {
			return []ir.Finding{mkFinding(s, r, "custom_features", span,
				f, "custom_features without 3DES/RC4/TLS_RSA_WITH_* suites")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-220: Target pool without health checks
// ---------------------------------------------------------------------------

type targetPoolNoHealthCheck struct{}

func (targetPoolNoHealthCheck) ID() string { return "AEGIS-GCP-220" }
func (targetPoolNoHealthCheck) Title() string {
	return "Target pool without health checks"
}
func (targetPoolNoHealthCheck) Description() string {
	return "google_compute_target_pool with no health_checks forwards " +
		"traffic without verifying instance health, and misses the signal " +
		"when an instance is compromised or failing. Attach a health " +
		"check."
}
func (targetPoolNoHealthCheck) Severity() ir.Severity { return ir.SeverityMedium }

func (targetPoolNoHealthCheck) AppliesTo(resType string) bool {
	return resType == "google_compute_target_pool"
}

func (s targetPoolNoHealthCheck) Check(r ir.Resource) []ir.Finding {
	empty, undecided := healthChecksEmpty(r, "health_checks")
	if undecided {
		return nil
	}
	if !empty {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "health_checks",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"health_checks = [google_compute_http_health_check.example.id]")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-221: VPC network with auto-created subnetworks
// ---------------------------------------------------------------------------

type networkAutoSubnetworks struct{}

func (networkAutoSubnetworks) ID() string { return "AEGIS-GCP-221" }
func (networkAutoSubnetworks) Title() string {
	return "VPC network with auto-created subnetworks"
}
func (networkAutoSubnetworks) Description() string {
	return "google_compute_network with auto_create_subnetworks enabled " +
		"(the provider default) creates a subnet in every region, " +
		"expanding the network footprint and attack surface. Use a " +
		"custom-mode VPC with explicitly declared subnetworks."
}
func (networkAutoSubnetworks) Severity() ir.Severity { return ir.SeverityMedium }

func (networkAutoSubnetworks) AppliesTo(resType string) bool {
	return resType == "google_compute_network"
}

func (s networkAutoSubnetworks) Check(r ir.Resource) []ir.Finding {
	auto, span, present, known := getBool(r, "auto_create_subnetworks")
	if present && !known {
		return nil
	}
	if present && !auto {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: true)"
	}
	return []ir.Finding{mkFinding(s, r, "auto_create_subnetworks",
		evidenceSpan(span, r.Span), actual,
		"auto_create_subnetworks = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-222: Firewall logging with metadata excluded
// ---------------------------------------------------------------------------

type fwLoggingNoMetadata struct{}

func (fwLoggingNoMetadata) ID() string { return "AEGIS-GCP-222" }
func (fwLoggingNoMetadata) Title() string {
	return "Firewall logging with metadata excluded"
}
func (fwLoggingNoMetadata) Description() string {
	return "google_compute_firewall log_config with metadata = " +
		"\"EXCLUDE_ALL_METADATA\" records flows without the metadata " +
		"needed for investigation. Use INCLUDE_ALL_METADATA."
}
func (fwLoggingNoMetadata) Severity() ir.Severity { return ir.SeverityLow }

func (fwLoggingNoMetadata) AppliesTo(resType string) bool {
	return resType == "google_compute_firewall"
}

func (s fwLoggingNoMetadata) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "log_config")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		md, span, mp, mk := blockString(b, "metadata")
		if mp && !mk {
			return nil
		}
		if mp && strings.EqualFold(strings.TrimSpace(md), "EXCLUDE_ALL_METADATA") {
			return []ir.Finding{mkFinding(s, r, "log_config.metadata", span,
				md, "metadata = \"INCLUDE_ALL_METADATA\"")}
		}
	}
	return nil
}
