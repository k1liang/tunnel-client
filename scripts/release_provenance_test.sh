#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${TUNNEL_CLIENT_PYTHON_RUNFILE:-}" ]]; then
  test_python="$(rlocation "${TUNNEL_CLIENT_PYTHON_RUNFILE}")"
  export PATH="$(dirname "${test_python}"):${PATH:-/usr/bin:/bin}"
fi

resolved_script_path="$(python3 - "${BASH_SOURCE[0]}" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
)"
script_dir="$(cd "$(dirname "${resolved_script_path}")" && pwd)"
if [[ -x "${script_dir}/scripts/verify_release_provenance.sh" ]]; then
  script_dir="${script_dir}/scripts"
fi
VERIFIER="$script_dir/verify_release_provenance.sh"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/tunnel-client-release-provenance-test.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

artifact_dir="$tmp_dir/artifacts"
fake_bin="$tmp_dir/bin"
bundle="$artifact_dir/tunnel-client-v0.0.0-provenance.sigstore.json"
verified_json="$tmp_dir/verified.json"
mkdir -p "$artifact_dir" "$fake_bin"

printf 'archive\n' >"$artifact_dir/tunnel-client-runtime-v0.0.0-linux-amd64.zip"
printf '{"spdxVersion":"SPDX-2.3"}\n' >"$artifact_dir/tunnel-client-runtime-v0.0.0-linux-amd64.spdx.json"
printf 'license report\n' >"$artifact_dir/tunnel-client-runtime-v0.0.0-linux-amd64-licenses.txt"
printf 'urls\n' >"$artifact_dir/PUBLIC_URLS.txt"
printf 'checksums\n' >"$artifact_dir/SHA256SUMS.txt"
printf '{"bundle":"fixture"}\n' >"$bundle"

write_verified_json() {
  local mode="$1"
  python3 - "$artifact_dir" "$bundle" "$verified_json" "$mode" <<'PY'
import hashlib
import json
import pathlib
import sys

artifact_dir = pathlib.Path(sys.argv[1])
bundle = pathlib.Path(sys.argv[2])
output = pathlib.Path(sys.argv[3])
mode = sys.argv[4]
subjects = []
for path in sorted(artifact_dir.iterdir()):
    if path == bundle:
        continue
    subjects.append(
        {
            "name": path.name,
            "digest": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
        }
    )
if mode == "bad-digest":
    subjects[0]["digest"]["sha256"] = "0" * 64
if mode == "missing-subject":
    subjects.pop()
if mode == "extra-subject":
    subjects.append({"name": "unexpected.txt", "digest": {"sha256": "1" * 64}})
output.write_text(
    json.dumps(
        [
            {
                "verificationResult": {
                    "statement": {
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "subject": subjects,
                    }
                }
            }
        ]
    )
    + "\n",
    encoding="utf-8",
)
PY
}

cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "attestation" && "${2:-}" == "verify" ]] || exit 91
args=" $* "
[[ "$args" == *" --bundle "* ]] || exit 92
[[ "$args" == *" --repo openai/tunnel-client "* ]] || exit 93
[[ "$args" == *" --signer-workflow openai/tunnel-client/.github/workflows/release.yml "* ]] || exit 94
[[ "$args" != *" --cert-identity "* ]] || exit 95
[[ "$args" == *" --source-ref refs/tags/v0.0.0 "* ]] || exit 96
[[ "$args" == *" --source-digest 0000000000000000000000000000000000000000 "* ]] || exit 97
[[ "$args" == *" --signer-digest 0000000000000000000000000000000000000000 "* ]] || exit 98
[[ "$args" == *" --predicate-type https://slsa.dev/provenance/v1 "* ]] || exit 99
[[ "$args" == *" --deny-self-hosted-runners "* ]] || exit 100
[[ "$args" == *" --format json "* ]] || exit 101
[[ "${FAKE_GH_FAIL:-}" != "1" ]] || exit 102
cat "$FAKE_GH_VERIFIED_JSON"
EOF
chmod +x "$fake_bin/gh"

run_verifier() {
  PATH="$fake_bin:$PATH" FAKE_GH_VERIFIED_JSON="$verified_json" \
    "$VERIFIER" \
    --bundle "$bundle" \
    --artifact-dir "$artifact_dir" \
    --release v0.0.0 \
    --source-digest 0000000000000000000000000000000000000000
}

assert_rejected() {
  local expected="$1"
  if run_verifier >"$tmp_dir/rejected.out" 2>&1; then
    echo "expected invalid provenance fixture to fail" >&2
    exit 1
  fi
  grep -F "$expected" "$tmp_dir/rejected.out" >/dev/null || {
    echo "expected failure containing: $expected" >&2
    cat "$tmp_dir/rejected.out" >&2
    exit 1
  }
}

assert_gh_failure_propagates() {
  if FAKE_GH_FAIL=1 run_verifier >"$tmp_dir/gh-failure.out" 2>&1; then
    echo "expected GitHub CLI verification failure to propagate" >&2
    exit 1
  fi
}

write_verified_json valid
run_verifier
assert_gh_failure_propagates
write_verified_json bad-digest
assert_rejected "verified SHA256 digest differs from release artifact"
write_verified_json missing-subject
assert_rejected "verified subject set differs from release artifacts"
write_verified_json extra-subject
assert_rejected "verified subject set differs from release artifacts"

ln -s SHA256SUMS.txt "$artifact_dir/symlink.txt"
write_verified_json valid
assert_rejected "artifact directory must contain only regular root files"

echo "release provenance verifier tests: passed"
