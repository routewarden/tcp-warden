#!/usr/bin/env bash
# scripts/update-version.sh
# TCP Warden version update and synchronization script.
#
# Usage:
#   ./scripts/update-version.sh              # Reads version directly from version.json and syncs files
#   ./scripts/update-version.sh v1.1.0       # Updates version.json and syncs across all files
#   ./scripts/update-version.sh 1.1.0        # Supports semver with or without 'v' prefix

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/version.json"

# Helper for cross-platform in-place sed (macOS BSD sed vs Linux GNU sed)
sed_inplace() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' -E "$@"
  else
    sed -i -E "$@"
  fi
}

# If a version argument was provided, update version.json first
if [ -n "${1:-}" ]; then
  RAW_VERSION="$1"

  # Ensure format has leading 'v'
  if [[ ! "$RAW_VERSION" =~ ^v ]]; then
    NEW_VERSION="v${RAW_VERSION}"
  else
    NEW_VERSION="${RAW_VERSION}"
  fi

  # Validate semver pattern (e.g. v1.0.0, v1.2.3, v1.0.0-rc.1)
  if [[ ! "$NEW_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "❌ Error: Invalid semantic version format: '$RAW_VERSION'"
    echo "Expected format: vMAJOR.MINOR.PATCH (e.g. v1.1.0, v1.0.1)"
    exit 1
  fi

  # Write back to version.json
  cat <<EOF > "$VERSION_FILE"
{
  "version": "${NEW_VERSION}"
}
EOF
fi

# Ensure version.json exists
if [ ! -f "$VERSION_FILE" ]; then
  echo "❌ Error: ${VERSION_FILE} not found and no version argument provided."
  echo "Usage: $0 [version]"
  exit 1
fi

# Extract version from version.json (compatible without requiring jq)
TARGET_VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$VERSION_FILE" | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$TARGET_VERSION" ]; then
  echo "❌ Error: Could not read 'version' key from ${VERSION_FILE}."
  exit 1
fi

SEMVER_NO_V="${TARGET_VERSION#v}"

echo "🔄 Synchronizing TCP Warden version: ${TARGET_VERSION} (${SEMVER_NO_V})"

UPDATED_COUNT=0

# 1. Update main.go (version = "X.Y.Z")
if [ -f "${ROOT_DIR}/main.go" ]; then
  sed_inplace "s|(version[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/main.go"
  echo "  ✓ Synchronized main.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 2. Update plugins/sdk/sdk.go (const Version = "X.Y.Z", ManifestVersion is preserved)
if [ -f "${ROOT_DIR}/plugins/sdk/sdk.go" ]; then
  sed_inplace "s|(const[[:space:]]+Version[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${ROOT_DIR}/plugins/sdk/sdk.go"
  echo "  ✓ Synchronized plugins/sdk/sdk.go"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 3. Update Dockerfile (ARG VERSION=X.Y.Z)
if [ -f "${ROOT_DIR}/Dockerfile" ]; then
  sed_inplace "s|(ARG[[:space:]]+VERSION=)[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|\1${SEMVER_NO_V}|g" "${ROOT_DIR}/Dockerfile"
  echo "  ✓ Synchronized Dockerfile"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 3. Update VERSIONING.md (example code snippet)
if [ -f "${ROOT_DIR}/VERSIONING.md" ]; then
  sed_inplace "s|(\"version\":[[:space:]]*\")v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${TARGET_VERSION}\3|g" "${ROOT_DIR}/VERSIONING.md"
  echo "  ✓ Synchronized VERSIONING.md"
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
fi

# 4. Update docs API references if present in parent repo
DOCS_DIR="${ROOT_DIR}/../docs/docs/tcp"
if [ -d "$DOCS_DIR" ]; then
  if [ -f "${DOCS_DIR}/api.md" ]; then
    sed_inplace "s|(\"version\":[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${DOCS_DIR}/api.md"
    echo "  ✓ Synchronized docs/docs/tcp/api.md"
    UPDATED_COUNT=$((UPDATED_COUNT + 1))
  fi
  if [ -f "${DOCS_DIR}/getting-started.md" ]; then
    sed_inplace "s|(\"version\":\")[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${SEMVER_NO_V}\3|g" "${DOCS_DIR}/getting-started.md"
    echo "  ✓ Synchronized docs/docs/tcp/getting-started.md"
    UPDATED_COUNT=$((UPDATED_COUNT + 1))
  fi
fi

echo ""
echo "✨ Successfully synchronized version ${TARGET_VERSION} across ${UPDATED_COUNT} target file(s)!"
echo "👉 Next steps:"
echo "   git diff"
echo "   git commit -am 'chore: release ${TARGET_VERSION}'"
echo "   git tag ${TARGET_VERSION}"
echo "   git push origin <branch> --tags"
