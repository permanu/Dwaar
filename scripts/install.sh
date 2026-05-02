#!/bin/sh
# Dwaar Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/permanu/Dwaar/main/scripts/install.sh | sh
# Or with a specific version:
#   DWAAR_VERSION=0.1.0 curl -fsSL ... | sh

set -eu

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
INSTALLER_VERSION="1.0"
GITHUB_REPO="permanu/Dwaar"
BINARY_NAME="dwaar"
SYSTEM_BIN="/usr/local/bin/dwaar"
USER_BIN="${HOME}/.local/bin/dwaar"
SYSTEM_CONFIG_DIR="/etc/dwaar"
SYSTEM_LOG_DIR="/var/log/dwaar"
SYSTEM_RUN_DIR="/run/dwaar"
SYSTEMD_UNIT="/etc/systemd/system/dwaar.service"

# ---------------------------------------------------------------------------
# Terminal colors (POSIX-safe: only emit when stdout is a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    BOLD="\033[1m"
    GREEN="\033[0;32m"
    CYAN="\033[0;36m"
    YELLOW="\033[0;33m"
    RED="\033[0;31m"
    RESET="\033[0m"
else
    BOLD=""
    GREEN=""
    CYAN=""
    YELLOW=""
    RED=""
    RESET=""
fi

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
info()    { printf "%b-> %b%s%b\n" "${CYAN}"  "${RESET}" "$*" "${RESET}"; }
success() { printf "%b✓  %b%s%b\n" "${GREEN}" "${RESET}" "$*" "${RESET}"; }
warn()    { printf "%b!  %b%s%b\n" "${YELLOW}" "${RESET}" "$*" "${RESET}"; }
die()     { printf "%bERROR: %s%b\n" "${RED}" "$*" "${RESET}" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Cleanup on exit — remove any temporary directory we created
# ---------------------------------------------------------------------------
TMPDIR_DWAAR=""
cleanup() {
    if [ -n "${TMPDIR_DWAAR}" ] && [ -d "${TMPDIR_DWAAR}" ]; then
        rm -rf "${TMPDIR_DWAAR}"
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
detect_platform() {
    OS=$(uname -s)
    ARCH=$(uname -m)

    case "${OS}" in
        Linux)  OS_KEY="linux"  ;;
        Darwin) OS_KEY="darwin" ;;
        *) die "Unsupported operating system: ${OS}. Only Linux and macOS are supported." ;;
    esac

    case "${ARCH}" in
        x86_64)          ARCH_KEY="amd64" ;;
        aarch64|arm64)   ARCH_KEY="arm64" ;;
        *) die "Unsupported architecture: ${ARCH}. Only x86_64 and aarch64/arm64 are supported." ;;
    esac

    ARTIFACT="${BINARY_NAME}-${OS_KEY}-${ARCH_KEY}"
    PLATFORM_LABEL="${OS} ${ARCH}"
}

# ---------------------------------------------------------------------------
# Resolve version — use DWAAR_VERSION env var or fetch latest from GitHub API
# ---------------------------------------------------------------------------
resolve_version() {
    if [ -n "${DWAAR_VERSION:-}" ]; then
        VERSION="${DWAAR_VERSION}"
        return
    fi

    info "Fetching latest release version from GitHub..."
    # Try curl first, then wget
    if command -v curl >/dev/null 2>&1; then
        LATEST=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
            | grep '"tag_name"' \
            | head -1 \
            | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        LATEST=$(wget -qO- "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
            | grep '"tag_name"' \
            | head -1 \
            | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/')
    else
        die "Neither curl nor wget is available. Please install one and retry."
    fi

    if [ -z "${LATEST}" ]; then
        die "Could not determine latest Dwaar version. Set DWAAR_VERSION=x.y.z to install a specific version."
    fi

    VERSION="${LATEST}"
}

# ---------------------------------------------------------------------------
# Download helper — curl with wget fallback
# ---------------------------------------------------------------------------
download() {
    URL="$1"
    DEST="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --progress-bar "${URL}" -o "${DEST}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress "${URL}" -O "${DEST}"
    else
        die "Neither curl nor wget is available. Please install one and retry."
    fi
}

# ---------------------------------------------------------------------------
# HEAD-style existence check — returns 0 if URL responds 2xx, 1 otherwise.
# Used to probe optional release assets (e.g. .bundle vs legacy .sig/.cert)
# without aborting the script under `set -e`.
# ---------------------------------------------------------------------------
http_exists() {
    URL="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSLI -o /dev/null "${URL}" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -q --spider "${URL}" >/dev/null 2>&1
    else
        die "Neither curl nor wget is available. Please install one and retry."
    fi
}

# ---------------------------------------------------------------------------
# SHA256 verification
# ---------------------------------------------------------------------------
verify_sha256() {
    BINARY_PATH="$1"
    CHECKSUM_FILE="$2"

    # Read the expected checksum — the .sha256 file may be "<hash>  filename" or just "<hash>"
    EXPECTED=$(awk '{print $1}' "${CHECKSUM_FILE}")

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "${BINARY_PATH}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "${BINARY_PATH}" | awk '{print $1}')
    else
        warn "No sha256sum or shasum found — skipping checksum verification."
        return 0
    fi

    if [ "${ACTUAL}" != "${EXPECTED}" ]; then
        die "SHA256 checksum mismatch!\n  expected: ${EXPECTED}\n  actual:   ${ACTUAL}\nThe download may be corrupted or tampered with."
    fi
}

# ---------------------------------------------------------------------------
# Privilege detection
# ---------------------------------------------------------------------------
running_as_root() {
    [ "$(id -u)" -eq 0 ]
}

has_sudo() {
    command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null
}

# ---------------------------------------------------------------------------
# Install binary — root → /usr/local/bin, sudo → /usr/local/bin, else ~/.local/bin
# ---------------------------------------------------------------------------
install_binary() {
    SRC="$1"

    if running_as_root; then
        cp "${SRC}" "${SYSTEM_BIN}"
        chmod +x "${SYSTEM_BIN}"
        INSTALL_PATH="${SYSTEM_BIN}"
    elif has_sudo; then
        sudo cp "${SRC}" "${SYSTEM_BIN}"
        sudo chmod +x "${SYSTEM_BIN}"
        INSTALL_PATH="${SYSTEM_BIN}"
    else
        # Non-root fallback: install to ~/.local/bin
        mkdir -p "${HOME}/.local/bin"
        cp "${SRC}" "${USER_BIN}"
        chmod +x "${USER_BIN}"
        INSTALL_PATH="${USER_BIN}"
        warn "Installed to ${USER_BIN} (no root/sudo). Make sure ~/.local/bin is in your PATH."
    fi
}

# ---------------------------------------------------------------------------
# Create system directories (Linux root only)
# ---------------------------------------------------------------------------
create_system_dirs() {
    if [ "${OS_KEY}" != "linux" ]; then
        return
    fi

    if running_as_root; then
        info "Creating ${SYSTEM_CONFIG_DIR}/..."
        mkdir -p "${SYSTEM_CONFIG_DIR}/apps" "${SYSTEM_LOG_DIR}" "${SYSTEM_RUN_DIR}"
        chmod 755 "${SYSTEM_LOG_DIR}" "${SYSTEM_RUN_DIR}"
    elif has_sudo; then
        info "Creating ${SYSTEM_CONFIG_DIR}/..."
        sudo mkdir -p "${SYSTEM_CONFIG_DIR}/apps" "${SYSTEM_LOG_DIR}" "${SYSTEM_RUN_DIR}"
        sudo chmod 755 "${SYSTEM_LOG_DIR}" "${SYSTEM_RUN_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# Write default Dwaarfile (never overwrite existing user config)
# ---------------------------------------------------------------------------
write_dwaarfile_system() {
    DWAARFILE="${SYSTEM_CONFIG_DIR}/Dwaarfile"

    if [ -f "${DWAARFILE}" ]; then
        warn "${DWAARFILE} already exists — not overwriting."
        return
    fi

    info "Creating ${DWAARFILE}..."

    CONTENT='{
    admin unix//run/dwaar/admin.sock

    auto_update {
        on_new_version reload
    }

    log default {
        output file /var/log/dwaar/access.log {
            roll_size_mb 50
            roll_keep    3
        }
        format json
        include http.log.access
    }
}

import /etc/dwaar/apps/*.dwaar'

    if running_as_root; then
        printf '%s\n' "${CONTENT}" > "${DWAARFILE}"
    elif has_sudo; then
        printf '%s\n' "${CONTENT}" | sudo tee "${DWAARFILE}" >/dev/null
    fi
}

write_dwaarfile_user() {
    USER_CONFIG_DIR="${HOME}/.config/dwaar"
    DWAARFILE="${USER_CONFIG_DIR}/Dwaarfile"

    if [ -f "${DWAARFILE}" ]; then
        warn "${DWAARFILE} already exists — not overwriting."
        return
    fi

    info "Creating ${DWAARFILE}..."
    mkdir -p "${USER_CONFIG_DIR}"

    printf '%s\n' '{
    admin unix//'"${HOME}"'/.local/run/dwaar/admin.sock

    log default {
        output file '"${HOME}"'/.local/log/dwaar/access.log {
            roll_size_mb 50
            roll_keep    3
        }
        format json
        include http.log.access
    }
}' > "${DWAARFILE}"
}

# ---------------------------------------------------------------------------
# Install systemd unit (Linux only, when systemd is present, never overwrite)
# ---------------------------------------------------------------------------
install_systemd_unit() {
    if [ "${OS_KEY}" != "linux" ]; then
        return
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd not found — skipping service installation."
        return
    fi

    if [ -f "${SYSTEMD_UNIT}" ]; then
        warn "${SYSTEMD_UNIT} already exists — not overwriting."
        # Always reload and re-enable in case binary path changed
        if running_as_root; then
            systemctl daemon-reload
            systemctl enable dwaar >/dev/null 2>&1 || true
        elif has_sudo; then
            sudo systemctl daemon-reload
            sudo systemctl enable dwaar >/dev/null 2>&1 || true
        fi
        return
    fi

    info "Installing systemd service..."

    UNIT_CONTENT='[Unit]
Description=Dwaar reverse proxy
After=network.target
Documentation=https://github.com/permanu/Dwaar

[Service]
Type=simple
ExecStart=/usr/local/bin/dwaar run --config /etc/dwaar/Dwaarfile
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target'

    if running_as_root; then
        printf '%s\n' "${UNIT_CONTENT}" > "${SYSTEMD_UNIT}"
        info "Enabling dwaar service..."
        systemctl daemon-reload
        systemctl enable dwaar >/dev/null 2>&1
    elif has_sudo; then
        printf '%s\n' "${UNIT_CONTENT}" | sudo tee "${SYSTEMD_UNIT}" >/dev/null
        info "Enabling dwaar service..."
        sudo systemctl daemon-reload
        sudo systemctl enable dwaar >/dev/null 2>&1
    fi
}

# ---------------------------------------------------------------------------
# Install macOS launchd plist (macOS only)
# ---------------------------------------------------------------------------
install_launchd_plist() {
    if [ "${OS_KEY}" != "darwin" ]; then
        return
    fi

    PLIST_DIR="${HOME}/Library/LaunchAgents"
    PLIST="${PLIST_DIR}/com.permanu.dwaar.plist"

    if [ -f "${PLIST}" ]; then
        warn "${PLIST} already exists — not overwriting."
        return
    fi

    info "Installing launchd agent..."
    mkdir -p "${PLIST_DIR}"

    cat > "${PLIST}" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.permanu.dwaar</string>

    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_PATH}</string>
        <string>run</string>
        <string>--config</string>
        <string>${HOME}/.config/dwaar/Dwaarfile</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>${HOME}/Library/Logs/dwaar/stdout.log</string>

    <key>StandardErrorPath</key>
    <string>${HOME}/Library/Logs/dwaar/stderr.log</string>
</dict>
</plist>
EOF

    mkdir -p "${HOME}/Library/Logs/dwaar"
    info "Loading launchd agent..."
    launchctl load "${PLIST}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Print quick start instructions
# ---------------------------------------------------------------------------
print_quickstart() {
    printf "\n"
    printf "%b✓ Dwaar v%s installed successfully!%b\n" "${GREEN}${BOLD}" "${VERSION}" "${RESET}"
    printf "\n"
    printf "Quick start:\n"
    printf "  dwaar version              # verify installation\n"
    printf "  dwaar run --config ...     # start with a config\n"

    if [ "${OS_KEY}" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
        printf "  systemctl start dwaar      # start the service\n"
        printf "  systemctl status dwaar     # check service status\n"
    elif [ "${OS_KEY}" = "darwin" ]; then
        printf "  launchctl start com.permanu.dwaar   # start the agent\n"
    fi

    if [ "${INSTALL_PATH}" = "${USER_BIN}" ]; then
        printf "\n"
        warn "~/.local/bin is your install location. Ensure it is in your PATH:"
        printf "  export PATH=\"\$HOME/.local/bin:\$PATH\"\n"
    fi
    printf "\n"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    printf "\n"
    printf "%bDwaar Installer v%s%b\n" "${BOLD}" "${INSTALLER_VERSION}" "${RESET}"
    printf "\n"

    # 1. Detect platform
    detect_platform
    printf "Detected: %s\n" "${PLATFORM_LABEL}"

    # 2. Resolve version
    resolve_version
    printf "Installing Dwaar v%s...\n\n" "${VERSION}"

    # 3. Create temp directory for downloads
    TMPDIR_DWAAR=$(mktemp -d)

    BINARY_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${ARTIFACT}"
    SHA256_URL="${BINARY_URL}.sha256"
    BINARY_TMP="${TMPDIR_DWAAR}/${ARTIFACT}"
    SHA256_TMP="${TMPDIR_DWAAR}/${ARTIFACT}.sha256"

    BUNDLE_URL="${BINARY_URL}.bundle"
    BUNDLE_TMP="${TMPDIR_DWAAR}/${ARTIFACT}.bundle"
    SIG_URL="${BINARY_URL}.sig"
    CERT_URL="${BINARY_URL}.cert"
    SIG_TMP="${TMPDIR_DWAAR}/${ARTIFACT}.sig"
    CERT_TMP="${TMPDIR_DWAAR}/${ARTIFACT}.cert"

    # 4. Download binary
    info "Downloading ${ARTIFACT}..."
    download "${BINARY_URL}" "${BINARY_TMP}"

    # 5. Download and verify SHA256 checksum
    info "Verifying SHA256 checksum..."
    download "${SHA256_URL}" "${SHA256_TMP}"
    verify_sha256 "${BINARY_TMP}" "${SHA256_TMP}"
    success "SHA256 checksum verified."

    # 5a. Cosign signature verification (keyless OIDC).
    #
    # As of v0.3.18 every release ships a single sigstore bundle
    # (`${ARTIFACT}.bundle`) that embeds both the signature and the Fulcio
    # certificate. Older releases shipped split `.sig` + `.cert` files; we
    # keep that path as a fallback so re-installs of historical versions
    # still verify cleanly.
    #
    # Verification chains to Fulcio with the GitHub Actions OIDC issuer and
    # pins the exact workflow path that produced this binary — a stronger
    # guarantee than sha256 alone (sha256 proves download integrity; cosign
    # proves build provenance).
    #
    # If cosign is NOT installed we fall back to sha256-only and print a
    # loud warning — we never silently bypass signature verification.
    info "Verifying cosign signature..."
    SIG_MODE=""
    if http_exists "${BUNDLE_URL}"; then
        download "${BUNDLE_URL}" "${BUNDLE_TMP}"
        SIG_MODE="bundle"
    elif http_exists "${SIG_URL}" && http_exists "${CERT_URL}"; then
        download "${SIG_URL}"  "${SIG_TMP}"
        download "${CERT_URL}" "${CERT_TMP}"
        SIG_MODE="legacy"
    else
        die "No signature artefacts found for ${ARTIFACT}. Looked for:
  ${BUNDLE_URL}
  ${SIG_URL} + ${CERT_URL}
Refusing to install an unverifiable binary."
    fi

    if command -v cosign >/dev/null 2>&1; then
        if [ "${SIG_MODE}" = "bundle" ]; then
            cosign verify-blob \
                --bundle "${BUNDLE_TMP}" \
                --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
                --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                "${BINARY_TMP}"
        else
            cosign verify-blob \
                --certificate "${CERT_TMP}" \
                --signature "${SIG_TMP}" \
                --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
                --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                "${BINARY_TMP}"
        fi
        success "Cosign signature verified (${SIG_MODE})."
    else
        printf "%bWarning: cosign not installed, skipping signature verification (sha256 still checked).%b\n" \
            "${YELLOW}" "${RESET}" >&2
        printf "%b         Install cosign from https://github.com/sigstore/cosign/releases%b\n" \
            "${YELLOW}" "${RESET}" >&2
        printf "%b         then verify manually:%b\n" "${YELLOW}" "${RESET}" >&2
        if [ "${SIG_MODE}" = "bundle" ]; then
            printf "%b         cosign verify-blob \\%b\n" "${YELLOW}" "${RESET}" >&2
            printf "%b           --bundle %s.bundle \\%b\n" "${YELLOW}" "${ARTIFACT}" "${RESET}" >&2
        else
            printf "%b         cosign verify-blob \\%b\n" "${YELLOW}" "${RESET}" >&2
            printf "%b           --certificate %s.cert \\%b\n" "${YELLOW}" "${ARTIFACT}" "${RESET}" >&2
            printf "%b           --signature %s.sig \\%b\n" "${YELLOW}" "${ARTIFACT}" "${RESET}" >&2
        fi
        printf '%b           --certificate-identity-regexp "^https://github\\.com/permanu/Dwaar/\\.github/workflows/release\\.yml@.*" \\%b\n' \
            "${YELLOW}" "${RESET}" >&2
        printf '%b           --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \\%b\n' \
            "${YELLOW}" "${RESET}" >&2
        printf "%b           %s%b\n" "${YELLOW}" "${ARTIFACT}" "${RESET}" >&2
    fi

    # 6. Install the binary (sets INSTALL_PATH)
    info "Installing to ${SYSTEM_BIN}..."
    install_binary "${BINARY_TMP}"
    success "Installed to ${INSTALL_PATH}."

    # 7. Create system directories (Linux root/sudo only)
    create_system_dirs

    # 8. Write default config if not present
    if [ "${INSTALL_PATH}" = "${SYSTEM_BIN}" ] && [ "${OS_KEY}" = "linux" ]; then
        write_dwaarfile_system
    elif [ "${OS_KEY}" = "darwin" ]; then
        write_dwaarfile_user
    fi

    # 9. Install service manager integration
    install_systemd_unit    # no-op on non-Linux or non-systemd
    install_launchd_plist   # no-op on non-macOS

    # 10. Done
    print_quickstart
}

main "$@"
