#!/usr/bin/env bash
# check-version-consistency.sh — Enforce that the version declared in
# Cargo.toml, LICENSE, and CHANGELOG.md is consistent, and that any bump
# is exactly one patch ahead of the latest published Git tag (or one
# minor / major if those components increment with patch=0 / minor=0).
#
# Run by .github/workflows/version-guard.yml on every PR; also runnable
# locally before opening a PR.
#
# Exits 0 if everything is consistent, non-zero with a descriptive
# error otherwise.

set -euo pipefail

CARGO_TOML="crates/dwaar-cli/Cargo.toml"
LICENSE_FILE="LICENSE"
CHANGELOG_FILE="CHANGELOG.md"

# --- Read the three sources of truth ---

cargo_version() {
    grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"$' "$CARGO_TOML" | head -1 | sed -E 's/version = "([^"]+)"/\1/'
}

license_version() {
    grep "Licensed Work:" "$LICENSE_FILE" | head -1 | awk '{print $NF}'
}

# Latest version that has a CHANGELOG section header (## [x.y.z]).
# Guards against "Unreleased" sneaking in as the canonical version.
changelog_top_version() {
    grep -m 1 -E '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$CHANGELOG_FILE" | sed -E 's/^## \[([^]]+)\].*/\1/'
}

# Latest released git tag (any v-prefixed semver). Sorted by version, not date.
latest_tag() {
    git tag -l 'v[0-9]*' | sort -V | tail -1 | sed 's/^v//'
}

# --- Semver helpers ---

split() { echo "$1" | tr '.' ' '; }

is_clean_increment() {
    # is_clean_increment <new> <old> → returns 0 if new is exactly old + 1 in
    # major / minor / patch (with zeros below), else returns 1.
    read -r oM om op <<<"$(split "$2")"
    read -r nM nm np <<<"$(split "$1")"

    # patch bump: same M.m, p = op + 1
    if [ "$nM" = "$oM" ] && [ "$nm" = "$om" ] && [ "$np" = "$((op + 1))" ]; then return 0; fi
    # minor bump: same M, m = om + 1, p = 0
    if [ "$nM" = "$oM" ] && [ "$nm" = "$((om + 1))" ] && [ "$np" = "0" ]; then return 0; fi
    # major bump: M = oM + 1, m = 0, p = 0
    if [ "$nM" = "$((oM + 1))" ] && [ "$nm" = "0" ] && [ "$np" = "0" ]; then return 0; fi
    return 1
}

# --- Run checks ---

CARGO=$(cargo_version)
LICENSE=$(license_version)
CL=$(changelog_top_version)
TAG=$(latest_tag)

printf 'Cargo.toml dwaar-cli version : %s\n' "$CARGO"
printf 'LICENSE Licensed Work version : %s\n' "$LICENSE"
printf 'CHANGELOG top entry version  : %s\n' "$CL"
printf 'Latest git tag                : %s\n' "$TAG"
echo

fail=0

if [ "$CARGO" != "$LICENSE" ]; then
    printf '✗ Cargo.toml (%s) does not match LICENSE (%s).\n' "$CARGO" "$LICENSE" >&2
    printf '  Run: ./scripts/bump-license-date.sh %s\n' "$CARGO" >&2
    fail=1
fi

if [ "$CARGO" != "$CL" ]; then
    printf '✗ Cargo.toml (%s) does not match top CHANGELOG entry (%s).\n' "$CARGO" "$CL" >&2
    printf "  Add a '## [%s] - YYYY-MM-DD' section to CHANGELOG.md.\n" "$CARGO" >&2
    fail=1
fi

# Only enforce the increment rule when the version actually moved past the
# latest tag — non-bumping PRs (most of them) leave Cargo.toml at the
# already-tagged value and that's fine.
if [ "$CARGO" != "$TAG" ]; then
    if ! is_clean_increment "$CARGO" "$TAG"; then
        printf '✗ Version skip detected.\n' >&2
        printf '  Latest tag : v%s\n' "$TAG" >&2
        printf '  Cargo.toml : %s\n' "$CARGO" >&2
        printf '  Allowed next versions:\n' >&2
        read -r M m p <<<"$(split "$TAG")"
        printf '    %s.%s.%s   (patch)\n' "$M" "$m" "$((p + 1))" >&2
        printf '    %s.%s.0     (minor)\n' "$M" "$((m + 1))" >&2
        printf '    %s.0.0       (major)\n' "$((M + 1))" >&2
        printf '  Either bump to one of those, or rebase onto main if a release was cut after your branch diverged.\n' >&2
        fail=1
    fi
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi

printf '✓ Version triple is consistent and the bump (if any) is a clean increment.\n'
