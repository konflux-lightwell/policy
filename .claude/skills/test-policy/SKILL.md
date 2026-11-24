---
name: test-policy
description: Use when running, testing, or verifying the Rego policy files in policy/. Triggers on "run policy tests", "test rego", "check policy", or before committing policy changes.
---

# Run Policy Tests

The `policy/` Rego files depend on `data.lib.*` from [conforma/policy](https://github.com/conforma/policy) and on `ec.oci.*` custom builtins from the `ec` CLI. Plain `opa` won't work.

## Setup (once)

Install the `ec` CLI binary:

```bash
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
VERSION=$(curl -sL https://api.github.com/repos/conforma/cli/releases/latest | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
curl -sL "https://github.com/conforma/cli/releases/download/${VERSION}/ec_${OS}_${ARCH}" \
  -o ~/.local/bin/ec && chmod +x ~/.local/bin/ec
```

## Command

Just run `make test` from the repo root — it fetches the pinned `data.lib.*`
dependency from [conforma/policy](https://github.com/conforma/policy) (version
pinned in the Makefile's `CONFORMA_LIB_REF`, currently `v1.0.31` — not `main`,
since `main` has drifted before, e.g. `parsed_blob_from_image` ->
`ec.oci.parsed_blob`) and runs `ec opa test` against all rule sets. This is
also what CI runs on every PR (`.github/workflows/policy-test.yml`).

To run a single test, run the underlying command directly and add `--run
<test_name>` before `--verbose`:

```bash
REPO_ROOT=$(git rev-parse --show-toplevel)
EC=~/.local/bin/ec
LIB="$REPO_ROOT/.claude/skills/test-policy/lib/lib"

"$EC" opa test \
  --ignore '*_test.rego' \
  "$LIB" \
  "$REPO_ROOT/policy/lightwell/distribution_target.rego" \
  "$REPO_ROOT/policy/lightwell/distribution_target_test.rego" \
  "$REPO_ROOT/policy/java/pnc_import.rego" \
  "$REPO_ROOT/policy/java/pnc_import_test.rego" \
  "$REPO_ROOT/policy/python/build_index_digest.rego" \
  "$REPO_ROOT/policy/python/build_index_digest_test.rego" \
  --run <test_name> \
  --verbose
```

To refresh the cached lib (e.g. after bumping `CONFORMA_LIB_REF`): `make clean-lib`
