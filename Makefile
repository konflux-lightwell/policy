EC ?= ~/.local/bin/ec
LIB := .claude/skills/test-policy/lib/lib

$(LIB):
	mkdir -p $(LIB)
	curl -sL https://github.com/conforma/policy/archive/refs/heads/main.tar.gz \
	  | tar xz --strip-components=2 -C .claude/skills/test-policy/lib "policy-main/policy/lib"

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
