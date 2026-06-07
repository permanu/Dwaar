#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

FAKE_BIN="${TMP_ROOT}/bin"
mkdir -p "${FAKE_BIN}"

cat > "${FAKE_BIN}/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' UnsupportedTestOS ;;
  -m) printf '%s\n' testarch ;;
  *) printf '%s\n' UnsupportedTestOS ;;
esac
EOF
chmod +x "${FAKE_BIN}/uname"

assert_contains() {
    file="$1"
    expected="$2"
    if ! grep -Fq -- "${expected}" "${file}"; then
        printf 'expected %s to contain: %s\n' "${file}" "${expected}" >&2
        printf 'actual:\n' >&2
        cat "${file}" >&2
        exit 1
    fi
}

run_case() {
    name="$1"
    expected_status="$2"
    body="$3"

    out="${TMP_ROOT}/${name}.out"
    if (
        PATH="${FAKE_BIN}:${PATH}"
        DWAAR_INSTALL_SH_LIBRARY=1
        export DWAAR_INSTALL_SH_LIBRARY
        # shellcheck disable=SC1091
        . "${REPO_ROOT}/scripts/install.sh"
        eval "${body}"
    ) >"${out}" 2>&1; then
        status=0
    else
        status=$?
    fi

    if [ "${status}" -ne "${expected_status}" ]; then
        printf 'case %s exited %s, expected %s\n' "${name}" "${status}" "${expected_status}" >&2
        cat "${out}" >&2
        exit 1
    fi

    printf '%s\n' "${out}"
}

cat > "${FAKE_BIN}/cosign" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" > "${COSIGN_ARGS_FILE}"
case "${COSIGN_BEHAVIOR:-pass}" in
  pass) exit 0 ;;
  fail) exit 42 ;;
  *) exit 2 ;;
esac
EOF
chmod +x "${FAKE_BIN}/cosign"

COSIGN_ARGS_FILE="${TMP_ROOT}/cosign.args"
export COSIGN_ARGS_FILE

out=$(run_case "key_path" 0 '
    ARTIFACT=dwaar-linux-amd64
    BINARY_TMP=/tmp/dwaar-linux-amd64
    BUNDLE_TMP=/tmp/dwaar-linux-amd64.bundle
    DWAAR_COSIGN_PUBKEY=/opt/dwaar/cosign.pub
    export DWAAR_COSIGN_PUBKEY
    verify_cosign_signature key
')
assert_contains "${COSIGN_ARGS_FILE}" "verify-blob /tmp/dwaar-linux-amd64 --bundle /tmp/dwaar-linux-amd64.bundle --key /opt/dwaar/cosign.pub"
assert_contains "${out}" "Cosign signature verified (Permanu/Dwaar release-authority key)."

out=$(run_case "keyless_bundle" 0 '
    ARTIFACT=dwaar-linux-amd64
    BINARY_TMP=/tmp/dwaar-linux-amd64
    BUNDLE_TMP=/tmp/dwaar-linux-amd64.bundle
    verify_cosign_signature keyless-bundle
')
assert_contains "${COSIGN_ARGS_FILE}" "verify-blob /tmp/dwaar-linux-amd64 --bundle /tmp/dwaar-linux-amd64.bundle --certificate-identity-regexp"
assert_contains "${out}" "Cosign signature verified (GitHub Actions keyless OIDC)."

out=$(run_case "keyless_cert" 0 '
    ARTIFACT=dwaar-linux-amd64
    BINARY_TMP=/tmp/dwaar-linux-amd64
    SIG_TMP=/tmp/dwaar-linux-amd64.sig
    CERT_TMP=/tmp/dwaar-linux-amd64.cert
    verify_cosign_signature keyless-cert
')
assert_contains "${COSIGN_ARGS_FILE}" "verify-blob /tmp/dwaar-linux-amd64 --certificate /tmp/dwaar-linux-amd64.cert --signature /tmp/dwaar-linux-amd64.sig"
assert_contains "${out}" "Cosign signature verified (GitHub Actions keyless OIDC)."

out=$(run_case "key_failure" 1 '
    ARTIFACT=dwaar-linux-amd64
    BINARY_TMP=/tmp/dwaar-linux-amd64
    BUNDLE_TMP=/tmp/dwaar-linux-amd64.bundle
    DWAAR_COSIGN_PUBKEY=/opt/dwaar/cosign.pub
    COSIGN_BEHAVIOR=fail
    export DWAAR_COSIGN_PUBKEY COSIGN_BEHAVIOR
    verify_cosign_signature key
')
assert_contains "${out}" "Cosign verification failed against the configured release key."

# A bundle-only release with no configured key must verify keylessly, NOT
# demand a public key. This is the regression that broke v0.3.23 installs.
out=$(run_case "keyless_bundle_failure_hint" 1 '
    ARTIFACT=dwaar-linux-amd64
    BINARY_TMP=/tmp/dwaar-linux-amd64
    BUNDLE_TMP=/tmp/dwaar-linux-amd64.bundle
    COSIGN_BEHAVIOR=fail
    export COSIGN_BEHAVIOR
    verify_cosign_signature keyless-bundle
')
assert_contains "${out}" "If this is an enterprise key-signed release"

printf 'install trust policy tests passed\n'
