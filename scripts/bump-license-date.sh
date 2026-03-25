#!/usr/bin/env bash
# bump-license-date.sh — Updates the BSL Change Date and Licensed Work version
# in LICENSE file on every release.
#
# Usage:
#   ./scripts/bump-license-date.sh 0.2.0          # bumps to version 0.2.0
#   ./scripts/bump-license-date.sh 1.0.0 --years 7  # custom protection period
#
# Called by CI during release workflow (tag push).

set -euo pipefail

VERSION="${1:?Usage: bump-license-date.sh <version> [--years N]}"
YEARS=6  # default: 6 years protection (same as SpacetimeDB)

# Parse optional --years flag
while [[ $# -gt 1 ]]; do
    case "$2" in
        --years)
            YEARS="${3:?--years requires a number}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

LICENSE_FILE="LICENSE"

if [[ ! -f "$LICENSE_FILE" ]]; then
    echo "ERROR: LICENSE file not found. Run from repo root."
    exit 1
fi

# Calculate new change date (current date + N years)
if [[ "$(uname)" == "Darwin" ]]; then
    NEW_DATE=$(date -v+"${YEARS}y" +%Y-%m-%d)
else
    NEW_DATE=$(date -d "+${YEARS} years" +%Y-%m-%d)
fi

CURRENT_YEAR=$(date +%Y)

echo "Bumping LICENSE:"
echo "  Version:     ${VERSION}"
echo "  Change Date: ${NEW_DATE} (${YEARS} years from today)"
echo ""

# Update Licensed Work version
sed -i.bak "s/Licensed Work:        Dwaar .*/Licensed Work:        Dwaar ${VERSION}/" "$LICENSE_FILE"

# Update copyright year
sed -i.bak "s/(c) [0-9]* Permanu/(c) ${CURRENT_YEAR} Permanu/" "$LICENSE_FILE"

# Update Change Date
sed -i.bak "s/Change Date:          .*/Change Date:          ${NEW_DATE}/" "$LICENSE_FILE"

# Clean up sed backup files
rm -f "${LICENSE_FILE}.bak"

# Verify changes
echo "Verification:"
grep "Licensed Work:" "$LICENSE_FILE" | head -1
grep "Change Date:" "$LICENSE_FILE" | head -1
grep "(c)" "$LICENSE_FILE" | head -1
echo ""
echo "Done. Commit this change as part of the release."
