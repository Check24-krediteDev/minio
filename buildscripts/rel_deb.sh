#!/usr/bin/env bash
# release-deb.sh — Build MinIO amd64 binary, package as .deb, and publish a GitHub release

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — edit or override via environment variables
# ---------------------------------------------------------------------------
GITHUB_TOKEN="${GITHUB_TOKEN:?'GITHUB_TOKEN env var is required'}"
GITHUB_REPO="${GITHUB_REPO:?'GITHUB_REPO env var is required (e.g. org/minio)'}"
VERSION="${VERSION:-$(git describe --tags --abbrev=0)}"
DEB_MAINTAINER="${DEB_MAINTAINER:-"Your Name <you@example.com>"}"

BINARY_NAME="minio"
PKG_NAME="${PKG_NAME:-minio-cve-2026-41145-fix}"  # Unique package name
ARCH="amd64"
DEB_FILE="${PKG_NAME}_${VERSION}_${ARCH}.deb"
SHA256_FILE="${DEB_FILE}.sha256"
BUILD_DIR="$(pwd)/_deb_build"

# ---------------------------------------------------------------------------
# 1. Install dpkg (macOS via Homebrew)
# ---------------------------------------------------------------------------
install_dpkg() {
  if command -v dpkg-deb &>/dev/null; then
    echo "✔ dpkg-deb already installed"
    return
  fi
  echo "→ Installing dpkg via Homebrew..."
  if ! command -v brew &>/dev/null; then
    echo "❌ Homebrew not found. Install it from https://brew.sh" && exit 1
  fi
  brew install dpkg
  echo "✔ dpkg installed"
}

# ---------------------------------------------------------------------------
# 2. Build the Linux amd64 binary
# ---------------------------------------------------------------------------
build_binary() {
  echo "→ Building Linux amd64 binary..."
  LDFLAGS=$(go run buildscripts/gen-ldflags.go)
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -tags kqueue -trimpath --ldflags "${LDFLAGS}" -o "${BINARY_NAME}"
  echo "✔ Binary built: $(pwd)/${BINARY_NAME}"
}

# ---------------------------------------------------------------------------
# 3. Create .deb package
# ---------------------------------------------------------------------------
build_deb() {
  echo "→ Creating .deb package..."
  rm -rf "${BUILD_DIR}"
  mkdir -p "${BUILD_DIR}/usr/local/bin"
  mkdir -p "${BUILD_DIR}/DEBIAN"

  cp "${BINARY_NAME}" "${BUILD_DIR}/usr/local/bin/${BINARY_NAME}"
  chmod 755 "${BUILD_DIR}/usr/local/bin/${BINARY_NAME}"

  cat > "${BUILD_DIR}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: ${DEB_MAINTAINER}
Homepage: https://github.com/${GITHUB_REPO}
Description: MinIO Object Storage Server (CVE-2026-41145 Security Fix)
 High-performance, S3-compatible object storage.
 This version includes security fixes for CVE-2026-41145.
 Built from: ${GITHUB_REPO}
EOF

  dpkg-deb --build "${BUILD_DIR}" "${DEB_FILE}"
  echo "✔ Package created: ${DEB_FILE}"
}

# ---------------------------------------------------------------------------
# 4. Compute SHA256 and optionally sign
# ---------------------------------------------------------------------------
compute_sha256() {
  echo "→ Computing SHA256..."
  shasum -a 256 "${DEB_FILE}" > "${SHA256_FILE}"
  echo "✔ SHA256: $(cat "${SHA256_FILE}")"
  
  # Optional: GPG signing for authenticity
  if [[ -n "${GPG_KEY_ID:-}" ]]; then
    echo "→ GPG signing with key ${GPG_KEY_ID}..."
    gpg --detach-sign --armor --default-key "${GPG_KEY_ID}" "${DEB_FILE}"
    gpg --detach-sign --armor --default-key "${GPG_KEY_ID}" "${SHA256_FILE}"
    echo "✔ GPG signatures created"
  fi
}

# ---------------------------------------------------------------------------
# 5. Create GitHub release and upload assets
# ---------------------------------------------------------------------------
release_to_github() {
  echo "→ Creating GitHub release ${VERSION}..."

  # Create the release
  RELEASE_RESPONSE=$(curl -sf -X POST \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Content-Type: application/json" \
    "https://api.github.com/repos/${GITHUB_REPO}/releases" \
    -d "{
      \"tag_name\": \"${VERSION}\",
      \"name\": \"${VERSION}\",
      \"body\": \"MinIO ${VERSION} — Linux amd64 .deb release\",
      \"draft\": false,
      \"prerelease\": false
    }")

  UPLOAD_URL=$(echo "${RELEASE_RESPONSE}" | grep -o '"upload_url": *"[^"]*"' \
    | sed 's/"upload_url": *"//;s/{.*}//')

  if [[ -z "${UPLOAD_URL}" ]]; then
    echo "❌ Failed to create release. Response:"
    echo "${RELEASE_RESPONSE}"
    exit 1
  fi

  echo "✔ Release created. Uploading assets..."

  upload_asset "${DEB_FILE}"  "application/vnd.debian.binary-package"
  upload_asset "${SHA256_FILE}" "text/plain"
  
  # Upload GPG signatures if they exist
  if [[ -f "${DEB_FILE}.asc" ]]; then
    upload_asset "${DEB_FILE}.asc" "text/plain"
  fi
  if [[ -f "${SHA256_FILE}.asc" ]]; then
    upload_asset "${SHA256_FILE}.asc" "text/plain"
  fi
}

upload_asset() {
  local file="$1"
  local mime="$2"
  local filename
  filename=$(basename "${file}")

  echo "  ↑ Uploading ${filename}..."
  curl -sf -X POST \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Content-Type: ${mime}" \
    "${UPLOAD_URL}$(basename "${file}")" \
    --data-binary @"${file}"
  echo "  ✔ Uploaded ${filename}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "=== MinIO deb release — version: ${VERSION} ==="
install_dpkg
build_binary
build_deb
compute_sha256
release_to_github
echo ""
echo "🎉 Done! Release ${VERSION} published to https://github.com/${GITHUB_REPO}/releases"