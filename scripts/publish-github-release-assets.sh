#!/bin/sh
set -eu

dist_dir="${1:-dist}"
repo="${GITHUB_REPOSITORY:-permanu/Dwaar}"
tag="${GITHUB_REF_NAME:-${GITHUB_REF##*/}}"
api_root="${GITHUB_API_URL:-https://api.github.com}"
token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "$2"
}

json_escape() {
    sed 's/\\/\\\\/g; s/"/\\"/g'
}

api_request() {
    method="$1"
    url="$2"
    body="${3:-}"

    if [ -n "$body" ]; then
        curl -fsSL \
            -X "$method" \
            -H "Authorization: Bearer ${token}" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            -H "Content-Type: application/json" \
            --data "$body" \
            "$url"
    else
        curl -fsSL \
            -X "$method" \
            -H "Authorization: Bearer ${token}" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$url"
    fi
}

release_upload_url() {
    response="$1"
    printf '%s' "$response" | tr '\n' ' ' | sed -n 's/.*"upload_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed 's/{.*//'
}

release_id() {
    response="$1"
    printf '%s' "$response" | tr '\n' ' ' | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p'
}

delete_existing_asset() {
    release_id_value="$1"
    name="$2"
    assets_url="${api_root}/repos/${repo}/releases/${release_id_value}/assets"
    asset_id=$(api_request GET "$assets_url" | tr '{' '\n' | grep "\"name\"[[:space:]]*:[[:space:]]*\"${name}\"" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1 || true)
    if [ -n "$asset_id" ]; then
        echo "Replacing existing ${name}"
        api_request DELETE "${api_root}/repos/${repo}/releases/assets/${asset_id}" >/dev/null
    fi
}

asset_upload() {
    upload_url="$1"
    release_id_value="$2"
    file="$3"
    name=$(basename "$file")
    encoded_name=$(printf '%s' "$name" | sed 's/+/%2B/g; s/ /%20/g; s/#/%23/g; s/?/%3F/g; s/&/%26/g')

    delete_existing_asset "$release_id_value" "$name"
    echo "Uploading ${name}"
    curl -fsSL \
        -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@${file}" \
        "${upload_url}?name=${encoded_name}" >/dev/null
}

case "$tag" in
    v*) ;;
    *) fail "GITHUB_REF_NAME/GITHUB_REF must identify a v* release tag" ;;
esac

[ -n "$token" ] || fail "GITHUB_TOKEN or GH_TOKEN is required to publish release assets"
[ -d "$dist_dir" ] || fail "release asset directory does not exist: ${dist_dir}"

require_cmd curl "curl is required to publish release assets"
require_cmd sed "sed is required to publish release assets"

release_name=$(printf '%s' "$tag" | json_escape)
body=$(printf '{"tag_name":"%s","name":"%s","draft":false,"prerelease":false,"generate_release_notes":false}' "$release_name" "$release_name")

release_url="${api_root}/repos/${repo}/releases/tags/${tag}"
create_url="${api_root}/repos/${repo}/releases"

if response=$(api_request GET "$release_url" 2>/dev/null); then
    echo "Updating existing GitHub release ${tag}"
else
    echo "Creating GitHub release ${tag}"
    response=$(api_request POST "$create_url" "$body")
fi

upload_url=$(release_upload_url "$response")
release_id_value=$(release_id "$response")
[ -n "$upload_url" ] || fail "GitHub release response did not include upload_url"
[ -n "$release_id_value" ] || fail "GitHub release response did not include id"

find "$dist_dir" -maxdepth 1 -type f | sort | while IFS= read -r file; do
    asset_upload "$upload_url" "$release_id_value" "$file"
done

echo "Published GitHub release assets for ${tag}."
