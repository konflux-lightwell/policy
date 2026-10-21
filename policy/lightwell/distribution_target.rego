# METADATA
# title: Lightwell Distribution Target Policy
# description: >-
#   Validates that a released image carries the correct dev.lightwell.distribution-target
#   OCI annotation, and (when a stream is configured) that the attached build-index
#   referrer contains the right class of vulnerability IDs for that stream.
#
#   This policy is ecosystem-agnostic and covers both Java (PNC) and Python builds.
#   The build-index referrer artifact type is configured per-stream via ruleData so
#   each ecosystem can point at its own referrer format.
#
#   Required ruleData keys:
#
#     lightwell_allowed_distribution_targets:
#       - validated
#
#   Optional stream-gate ruleData (omit to disable vuln-class checks):
#
#     lightwell_build_index_artifact_type: application/vnd.lightwell.build-index.v1+json
#       # Java:   application/vnd.redhat.gav-index-build+json
#       # Python: application/vnd.lightwell.build-index.v1+json
#
#     lightwell_novel_vuln_id_prefixes:
#       - LW-
#
#     lightwell_cve_vuln_id_prefixes:
#       - CVE-
#
package lightwell

import rego.v1

import data.lib.json as j
import data.lib.metadata
import data.lib.oci
import data.lib.rule_data

# ---------------------------------------------------------------------------
# Distribution target annotation check
# ---------------------------------------------------------------------------

# METADATA
# title: Distribution target annotation present
# description: >-
#   Verify the dev.lightwell.distribution-target annotation is present on the
#   released image's OCI manifest.
# custom:
#   short_name: distribution_target_annotation_present
#   failure_msg: 'dev.lightwell.distribution-target annotation is absent from the image manifest'
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	manifest := ec.oci.image_manifest(input.image.ref)
	not manifest.annotations["dev.lightwell.distribution-target"]
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Distribution target annotation permitted
# description: >-
#   Verify the dev.lightwell.distribution-target annotation on the released
#   image is in the set of allowed values configured for this release stream.
# custom:
#   short_name: distribution_target_permitted
#   failure_msg: >-
#     dev.lightwell.distribution-target annotation %q is not in the allowed set.
#     Allowed: %v
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	annotation := _distribution_target_annotation
	not annotation in _allowed_distribution_targets
	result := metadata.result_helper(rego.metadata.chain(), [annotation, _allowed_distribution_targets])
}

# METADATA
# title: Distribution target ruleData provided
# description: >-
#   Confirm lightwell_allowed_distribution_targets was provided in ruleData.
# custom:
#   short_name: distribution_target_rule_data_provided
#   failure_msg: '%s'
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	some e in _distribution_target_rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# ---------------------------------------------------------------------------
# Vulnerability-class gate (per release stream)
#
# Opt-in via lightwell_build_index_artifact_type ruleData.
# The stream is derived from the dev.lightwell.distribution-target annotation:
#
#   novel | predisclosed → novel  : must have >=1 vuln id (LW- or CVE-)
#   backport | remediated → backport : must have >=1 CVE; must have NO LW- vuln ids
#   validated             → validated: must have NO vuln ids at all (clean upstream rebuild)
# ---------------------------------------------------------------------------

# METADATA
# title: Build index referrer present
# description: >-
#   Verify a build-index artifact is attached to the released image via the OCI
#   Referrers API. Absence means the content cannot be classified (fail-closed).
# custom:
#   short_name: build_index_referrer_present
#   failure_msg: >-
#     no build-index referrer (artifactType %q) is attached to the released image
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	_stream_gate_enabled
	count(_build_index_referrers) == 0
	result := metadata.result_helper(rego.metadata.chain(), [_build_index_artifact_type])
}

# METADATA
# title: Novel requires a vulnerability id
# description: >-
#   The novel stream must carry at least one vuln id (LW- or CVE-).
# custom:
#   short_name: novel_requires_vuln
#   failure_msg: 'novel stream requires at least one vuln id (LW- or CVE-), found none'
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	_stream == "novel"
	count(_build_index_referrers) > 0
	not _has_vuln
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Backport requires a CVE vulnerability
# description: >-
#   The backport stream must carry at least one CVE vuln id.
# custom:
#   short_name: backport_requires_cve
#   failure_msg: 'backport stream requires at least one CVE vuln id, found none'
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	_stream == "backport"
	count(_build_index_referrers) > 0
	not _has_cve
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Backport excludes novel vulnerabilities
# description: >-
#   The backport stream must not carry any LW- vuln id — novel content must not
#   reach the remediated channel.
# custom:
#   short_name: backport_excludes_novel
#   failure_msg: 'backport stream must not contain novel (LW-) vuln ids: %v'
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	_stream == "backport"
	_has_novel
	result := metadata.result_helper(rego.metadata.chain(), [_novel_vulns])
}

# METADATA
# title: Validated excludes all vulnerabilities
# description: >-
#   The validated stream is a clean upstream rebuild and must carry no vuln ids at all,
#   regardless of prefix.
# custom:
#   short_name: validated_excludes_all_vulns
#   failure_msg: 'validated stream must contain no vuln ids, found: %v'
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	_stream == "validated"
	count(_build_index_vulns) > 0
	result := metadata.result_helper(rego.metadata.chain(), [_build_index_vulns])
}

# METADATA
# title: Vuln-id prefix ruleData provided
# description: >-
#   When a novel or backport stream is configured, both lightwell_novel_vuln_id_prefixes
#   and lightwell_cve_vuln_id_prefixes must be provided. Validated stream checks for
#   the absence of all vulns and does not require prefix lists.
# custom:
#   short_name: vuln_prefix_rule_data_provided
#   failure_msg: '%s'
#   collections:
#     - lightwell
#     - lightwell-generic
deny contains result if {
	_stream_gate_enabled
	_stream != "validated"
	some e in _vuln_prefix_rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_distribution_target_annotation := annotation if {
	manifest := ec.oci.image_manifest(input.image.ref)
	annotation := manifest.annotations["dev.lightwell.distribution-target"]
}

# Maps the annotation value to the vuln-class gate stream name.
_target_to_stream := {
	"novel":       "novel",
	"predisclosed": "novel",
	"backport":    "backport",
	"remediated":  "backport",
	"validated":   "validated",
}

_stream := _target_to_stream[_distribution_target_annotation]

_stream_gate_enabled if is_string(_build_index_artifact_type)

_build_index_artifact_type := rule_data.get("lightwell_build_index_artifact_type")

_build_index_referrers contains r if {
	some r in ec.oci.image_referrers(input.image.ref)
	r.artifactType == _build_index_artifact_type
}

_build_index_vulns contains v if {
	some r in _build_index_referrers
	raw := oci.blob_from_image(r.ref)
	json.is_valid(raw)
	doc := json.unmarshal(raw)
	some v in doc.vulns
}

_is_novel_vuln(v) if {
	some prefix in _novel_vuln_id_prefixes
	startswith(v, prefix)
}

_is_cve_vuln(v) if {
	some prefix in _cve_vuln_id_prefixes
	startswith(v, prefix)
}

_novel_vulns := {v | some v in _build_index_vulns; _is_novel_vuln(v)}

_cve_vulns := {v | some v in _build_index_vulns; _is_cve_vuln(v)}

_has_novel if count(_novel_vulns) > 0

_has_cve if count(_cve_vulns) > 0

_has_vuln if _has_novel

_has_vuln if _has_cve

_novel_vuln_id_prefixes := rule_data.get("lightwell_novel_vuln_id_prefixes")

_cve_vuln_id_prefixes := rule_data.get("lightwell_cve_vuln_id_prefixes")

# ---------------------------------------------------------------------------
# ruleData accessors with schema validation
# ---------------------------------------------------------------------------

_allowed_distribution_targets := rule_data.get("lightwell_allowed_distribution_targets")

_string_list_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "array",
	"items": {"type": "string"},
	"uniqueItems": true,
	"minItems": 1,
}

_distribution_target_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get("lightwell_allowed_distribution_targets"),
		_string_list_schema,
	)
	error := {"message": e.message, "severity": e.severity}
}

_vuln_prefix_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get("lightwell_novel_vuln_id_prefixes"),
		_string_list_schema,
	)
	error := {"message": e.message, "severity": e.severity}
}

_vuln_prefix_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get("lightwell_cve_vuln_id_prefixes"),
		_string_list_schema,
	)
	error := {"message": e.message, "severity": e.severity}
}
