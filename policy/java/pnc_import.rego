# METADATA
# title: PNC Import Trust Policy
# description: >-
#   Validates that the oci-verify-import task operated on an approved source
#   registry and used an approved signing key, and that the GAV index attached
#   to the released image contains at least one GAV.
#
#   Distribution target and vuln-class checks are handled by the lightwell
#   package (policy/lightwell/distribution_target.rego); include both in the ECP.
#
#   Required ruleData keys:
#
#     oci_verify_import_allowed_source_registries:
#       - quay.io/light-castle/rebuild-pnc
#
#     oci_verify_import_allowed_signing_keys:
#       - SHA256:abcd...
#
package pnc_import

import rego.v1

import data.lib.json as j
import data.lib.metadata
import data.lib.oci
import data.lib.rule_data

# ---------------------------------------------------------------------------
# Source registry check
# ---------------------------------------------------------------------------

# METADATA
# title: Source registry permitted
# description: >-
#   Verify the SOURCE_IMAGE parameter of the oci-verify-import task originates
#   from an allowed source registry.
# custom:
#   short_name: source_registry_permitted
#   failure_msg: >-
#     SOURCE_IMAGE %q does not start with any allowed source registry prefix.
#     Allowed: %v
#   collections:
#     - lightwell
deny contains result if {
	some source_image in _source_images
	not _source_image_permitted(source_image)
	result := metadata.result_helper(rego.metadata.chain(), [source_image, _allowed_source_registries])
}

# METADATA
# title: Source registry ruleData provided
# description: >-
#   Confirm oci_verify_import_allowed_source_registries was provided in ruleData.
# custom:
#   short_name: source_registry_rule_data_provided
#   failure_msg: '%s'
#   collections:
#     - lightwell
deny contains result if {
	some e in _source_registry_rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# ---------------------------------------------------------------------------
# Signing key fingerprint check
# ---------------------------------------------------------------------------

# METADATA
# title: Signing key permitted
# description: >-
#   Verify the VERIFICATION_KEY_FINGERPRINT result of the oci-verify-import task
#   is in the approved set.
# custom:
#   short_name: signing_key_permitted
#   failure_msg: >-
#     VERIFICATION_KEY_FINGERPRINT %q is not in the allowed set. Allowed: %v
#   collections:
#     - lightwell
deny contains result if {
	some fingerprint in _signing_key_fingerprints
	not fingerprint in _allowed_signing_keys
	result := metadata.result_helper(rego.metadata.chain(), [fingerprint, _allowed_signing_keys])
}

# METADATA
# title: Signing key result present
# description: >-
#   Confirm the oci-verify-import task emitted a VERIFICATION_KEY_FINGERPRINT result.
# custom:
#   short_name: signing_key_result_present
#   failure_msg: 'VERIFICATION_KEY_FINGERPRINT result not found in any oci-verify-import task'
#   collections:
#     - lightwell
deny contains result if {
	count(_signing_key_fingerprints) == 0
	count(_pipelinerun_attestations) > 0
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Signing key ruleData provided
# description: >-
#   Confirm oci_verify_import_allowed_signing_keys was provided in ruleData.
# custom:
#   short_name: signing_key_rule_data_provided
#   failure_msg: '%s'
#   collections:
#     - lightwell
deny contains result if {
	some e in _signing_key_rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# ---------------------------------------------------------------------------
# GAV present (Java-specific: ensures the GAV index referrer has content)
# ---------------------------------------------------------------------------

# METADATA
# title: GAV present
# description: >-
#   Every release stream requires at least one GAV in the GAV index referrer.
# custom:
#   short_name: gav_present
#   failure_msg: 'the GAV index contains no GAVs'
#   collections:
#     - lightwell
deny contains result if {
	count(_gav_index_referrers) > 0
	not _has_gav
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# ---------------------------------------------------------------------------
# Helpers — extract input parameters from SLSA PipelineRun attestations
# ---------------------------------------------------------------------------

_source_images contains img if {
	some att in _pipelinerun_attestations
	att.statement.predicateType == "https://slsa.dev/provenance/v0.2"
	img := att.statement.predicate.invocation.parameters.SOURCE_IMAGE
}

_source_images contains img if {
	some att in _pipelinerun_attestations
	att.statement.predicateType == "https://slsa.dev/provenance/v1"
	some p in att.statement.predicate.buildDefinition.externalParameters.runSpec.params
	p.name == "SOURCE_IMAGE"
	img := p.value
}

_signing_key_fingerprints contains fp if {
	some att in _pipelinerun_attestations
	att.statement.predicateType == "https://slsa.dev/provenance/v0.2"
	some task in att.statement.predicate.buildConfig.tasks
	some r in task.results
	r.name == "VERIFICATION_KEY_FINGERPRINT"
	fp := r.value
}

_signing_key_fingerprints contains fp if {
	some att in _pipelinerun_attestations
	att.statement.predicateType == "https://slsa.dev/provenance/v1"
	some bp in att.statement.predicate.runDetails.byproducts
	_name_matches(bp.name, "VERIFICATION_KEY_FINGERPRINT")
	fp := json.unmarshal(base64.decode(bp.content))
}

_pipelinerun_attestations contains att if {
	some att in input.attestations
	att.statement.predicateType in {
		"https://slsa.dev/provenance/v0.2",
		"https://slsa.dev/provenance/v1",
	}
}

_source_image_permitted(source_image) if {
	some prefix in _allowed_source_registries
	startswith(source_image, prefix)
}

_name_matches(name, target) if name == target

_name_matches(name, target) if endswith(name, concat("", ["/", target]))

_gav_index_artifact_type := "application/vnd.redhat.gav-index-build+json"

_gav_index_referrers contains r if {
	some r in ec.oci.image_referrers(input.image.ref)
	r.artifactType == _gav_index_artifact_type
}

_gav_index_gavs contains g if {
	some r in _gav_index_referrers
	raw := oci.blob_from_image(r.ref)
	json.is_valid(raw)
	doc := json.unmarshal(raw)
	some g in doc.gavs
}

_has_gav if count(_gav_index_gavs) > 0

# ---------------------------------------------------------------------------
# ruleData accessors with schema validation
# ---------------------------------------------------------------------------

_allowed_source_registries := rule_data.get("oci_verify_import_allowed_source_registries")

_allowed_signing_keys := rule_data.get("oci_verify_import_allowed_signing_keys")

_string_list_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "array",
	"items": {"type": "string"},
	"uniqueItems": true,
	"minItems": 1,
}

_source_registry_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get("oci_verify_import_allowed_source_registries"),
		_string_list_schema,
	)
	error := {"message": e.message, "severity": e.severity}
}

_signing_key_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get("oci_verify_import_allowed_signing_keys"),
		_string_list_schema,
	)
	error := {"message": e.message, "severity": e.severity}
}
