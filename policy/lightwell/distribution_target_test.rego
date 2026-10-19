package lightwell_test

import rego.v1

import data.lightwell

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

_image_ref := "quay.io/redhat-user-workloads/lightwell-poc-tenant/image@sha256:abc123"

_allowed_validated := ["validated"]
_allowed_remediated := ["remediated"]
_allowed_backport := ["backport"]
_allowed_novel := ["novel"]
_allowed_migration := ["remediated", "novel"]

_novel_prefixes := ["LW-"]
_cve_prefixes := ["CVE-"]

# Java referrer type (GAV index)
_java_artifact_type := "application/vnd.redhat.gav-index-build+json"

# Python referrer type (build-index)
_python_artifact_type := "application/vnd.lightwell.build-index.v1+json"

_referrer_ref := "quay.io/redhat-user-workloads/lightwell-poc-tenant/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

_mock_no_referrers(_) := []

_mock_manifest_validated(_) := {"annotations": {"dev.lightwell.distribution-target": "validated"}}

_mock_manifest_remediated(_) := {"annotations": {"dev.lightwell.distribution-target": "remediated"}}

_mock_manifest_backport(_) := {"annotations": {"dev.lightwell.distribution-target": "backport"}}

_mock_manifest_novel(_) := {"annotations": {"dev.lightwell.distribution-target": "novel"}}

_mock_manifest_no_annotation(_) := {"annotations": {}}

_mock_blob_manifest(_) := {"layers": [{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}

_mock_blob_manifest_validated(_) := {
	"annotations": {"dev.lightwell.distribution-target": "validated"},
	"layers": [{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
}

_mock_blob_manifest_novel(_) := {
	"annotations": {"dev.lightwell.distribution-target": "novel"},
	"layers": [{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
}

_mock_blob_manifest_remediated(_) := {
	"annotations": {"dev.lightwell.distribution-target": "remediated"},
	"layers": [{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
}

_mock_blob_manifest_backport(_) := {
	"annotations": {"dev.lightwell.distribution-target": "backport"},
	"layers": [{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
}

# blob variants: vulns field covers both java (gavs+vulns) and python (primaryPurl+vulns)
_blob_cve(_) := "{\"gavs\": [\"g:a:1\"], \"primaryPurl\": \"pkg:pypi/foo@1.0\", \"vulns\": [\"CVE-2021-37533\"]}"

_blob_novel(_) := "{\"gavs\": [\"g:a:1\"], \"primaryPurl\": \"pkg:pypi/foo@1.0\", \"vulns\": [\"LW-2026-4259\"]}"

_blob_mixed(_) := "{\"gavs\": [\"g:a:1\"], \"primaryPurl\": \"pkg:pypi/foo@1.0\", \"vulns\": [\"CVE-2025-48924\", \"LW-2026-0092\"]}"

_blob_clean(_) := "{\"gavs\": [\"g:a:1\"], \"primaryPurl\": \"pkg:pypi/foo@1.0\", \"vulns\": []}"

# ---------------------------------------------------------------------------
# Distribution target annotation
# ---------------------------------------------------------------------------

test_annotation_present_and_permitted if {
	count(lightwell.deny) == 0 with input.image.ref as _image_ref
		with input.attestations as []
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_validated
		with ec.oci.image_manifest as _mock_manifest_validated
}

test_annotation_absent_denied if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with input.attestations as []
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_validated
		with ec.oci.image_manifest as _mock_manifest_no_annotation
	_has_code(deny, "lightwell.distribution_target_annotation_present")
}

test_annotation_wrong_value_denied if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with input.attestations as []
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_validated
		with ec.oci.image_manifest as _mock_manifest_remediated
	_has_code(deny, "lightwell.distribution_target_permitted")
}

test_annotation_rule_data_missing_denied if {
	some r in lightwell.deny with input.image.ref as _image_ref
		with input.attestations as []
		with data.rule_data_custom.lightwell_allowed_distribution_targets as null
		with ec.oci.image_manifest as _mock_manifest_validated
	r.code == "lightwell.distribution_target_rule_data_provided"
}

# ---------------------------------------------------------------------------
# Stream gate — validated (no CVE, no LW-)
# ---------------------------------------------------------------------------

test_validated_accepts_clean_java if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_validated
		with ec.oci.blob as _blob_clean
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_validated
		with data.rule_data_custom.lightwell_stream as "validated"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	not _has_code(deny, "lightwell.validated_excludes_cve")
	not _has_code(deny, "lightwell.validated_excludes_novel")
}

test_validated_accepts_clean_python if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _python_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_validated
		with ec.oci.blob as _blob_clean
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_validated
		with data.rule_data_custom.lightwell_stream as "validated"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _python_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	not _has_code(deny, "lightwell.validated_excludes_cve")
	not _has_code(deny, "lightwell.validated_excludes_novel")
}

test_validated_rejects_cve if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_validated
		with ec.oci.blob as _blob_cve
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_validated
		with data.rule_data_custom.lightwell_stream as "validated"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	_has_code(deny, "lightwell.validated_excludes_cve")
}

test_validated_rejects_novel if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_validated
		with ec.oci.blob as _blob_novel
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_validated
		with data.rule_data_custom.lightwell_stream as "validated"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	_has_code(deny, "lightwell.validated_excludes_novel")
}

# ---------------------------------------------------------------------------
# Stream gate — backport (>=1 CVE, no LW-)
# ---------------------------------------------------------------------------

test_backport_accepts_cve if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_backport
		with ec.oci.blob as _blob_cve
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_backport
		with data.rule_data_custom.lightwell_stream as "backport"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	not _has_code(deny, "lightwell.backport_requires_cve")
	not _has_code(deny, "lightwell.backport_excludes_novel")
}

test_backport_rejects_novel_content if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_backport
		with ec.oci.blob as _blob_mixed
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_backport
		with data.rule_data_custom.lightwell_stream as "backport"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	_has_code(deny, "lightwell.backport_excludes_novel")
}

test_backport_rejects_no_cve if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_backport
		with ec.oci.blob as _blob_novel
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_backport
		with data.rule_data_custom.lightwell_stream as "backport"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	_has_code(deny, "lightwell.backport_requires_cve")
}

# ---------------------------------------------------------------------------
# Stream gate — novel (>=1 vuln of any kind)
# ---------------------------------------------------------------------------

test_novel_accepts_lw if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _python_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_novel
		with ec.oci.blob as _blob_novel
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_novel
		with data.rule_data_custom.lightwell_stream as "novel"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _python_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	not _has_code(deny, "lightwell.novel_requires_vuln")
}

test_novel_accepts_cve if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _python_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_novel
		with ec.oci.blob as _blob_cve
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_novel
		with data.rule_data_custom.lightwell_stream as "novel"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _python_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	not _has_code(deny, "lightwell.novel_requires_vuln")
}

test_novel_rejects_empty_vulns if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _python_referrers
		with ec.oci.image_manifest as _mock_blob_manifest_novel
		with ec.oci.blob as _blob_clean
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_novel
		with data.rule_data_custom.lightwell_stream as "novel"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _python_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	_has_code(deny, "lightwell.novel_requires_vuln")
}

# ---------------------------------------------------------------------------
# Stream gate — referrer missing
# ---------------------------------------------------------------------------

test_missing_referrer_denied if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_no_referrers
		with data.rule_data_custom.lightwell_stream as "backport"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	_has_code(deny, "lightwell.build_index_referrer_present")
}

test_gate_inert_without_stream if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_no_referrers
		with data.rule_data_custom.lightwell_allowed_distribution_targets as _allowed_validated
		with ec.oci.image_manifest as _mock_manifest_validated
	not _has_code(deny, "lightwell.build_index_referrer_present")
}

# ---------------------------------------------------------------------------
# Stream ruleData validation
# ---------------------------------------------------------------------------

test_invalid_stream_denied if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest
		with ec.oci.blob as _blob_clean
		with data.rule_data_custom.lightwell_stream as "unknown"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	_has_code(deny, "lightwell.stream_rule_data_valid")
}

test_empty_novel_prefixes_denied if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest
		with ec.oci.blob as _blob_cve
		with data.rule_data_custom.lightwell_stream as "backport"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as []
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as _cve_prefixes
	_has_code(deny, "lightwell.vuln_prefix_rule_data_provided")
}

test_empty_cve_prefixes_denied if {
	deny := lightwell.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _java_referrers
		with ec.oci.image_manifest as _mock_blob_manifest
		with ec.oci.blob as _blob_cve
		with data.rule_data_custom.lightwell_stream as "backport"
		with data.rule_data_custom.lightwell_build_index_artifact_type as _java_artifact_type
		with data.rule_data_custom.lightwell_novel_vuln_id_prefixes as _novel_prefixes
		with data.rule_data_custom.lightwell_cve_vuln_id_prefixes as []
	_has_code(deny, "lightwell.vuln_prefix_rule_data_provided")
}

# ---------------------------------------------------------------------------
# Helpers — referrer mock functions
# ---------------------------------------------------------------------------

_java_referrers(_) := [{"artifactType": _java_artifact_type, "ref": _referrer_ref}]

_python_referrers(_) := [{"artifactType": _python_artifact_type, "ref": _referrer_ref}]

_has_code(deny, code) if {
	some r in deny
	r.code == code
}
