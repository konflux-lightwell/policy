EC ?= ~/.local/bin/ec
# Pinned so a drift on conforma/policy main (e.g. the past
# parsed_blob_from_image -> ec.oci.parsed_blob rename) can't silently break
# these tests. Bump deliberately and re-run `make test` to confirm.
CONFORMA_LIB_REF := v1.0.31
LIB := .claude/skills/test-policy/lib/lib

$(LIB):
	mkdir -p $(LIB)
	curl -sL "https://github.com/conforma/policy/archive/refs/tags/$(CONFORMA_LIB_REF).tar.gz" \
	  | tar xz --strip-components=2 -C .claude/skills/test-policy/lib "policy-$$(echo $(CONFORMA_LIB_REF) | sed 's/^v//')/policy/lib"

.PHONY: test
test: $(LIB)
	$(EC) opa test \
	  --ignore '*_test.rego' \
	  $(LIB) \
	  policy/lightwell/distribution_target.rego \
	  policy/lightwell/distribution_target_test.rego \
	  policy/java/pnc_import.rego \
	  policy/java/pnc_import_test.rego \
	  policy/python/build_index_digest.rego \
	  policy/python/build_index_digest_test.rego \
	  --verbose

.PHONY: clean-lib
clean-lib:
	rm -rf .claude/skills/test-policy/lib
