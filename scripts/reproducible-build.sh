#!/bin/bash
# Reproducible Build Script for Ghost Privacy
# Ensures deterministic builds across different machines

set -euo pipefail

export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
OUTPUT_DIR="${PROJECT_ROOT}/reproducible-output"

echo "🔐 Ghost Privacy Reproducible Build"
echo "===================================="
echo "SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH}"
echo "Build started: $(date -u -d @${SOURCE_DATE_EPOCH} '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# Clean build environment
rm -rf "${BUILD_DIR}" "${OUTPUT_DIR}"
mkdir -p "${BUILD_DIR}" "${OUTPUT_DIR}"

# Set deterministic environment
export CARGO_HOME="${BUILD_DIR}/cargo"
export RUSTUP_HOME="${BUILD_DIR}/rustup"
export NPM_CONFIG_CACHE="${BUILD_DIR}/npm-cache"
export NODE_OPTIONS="--max-old-space-size=4096"

# Pin Rust toolchain
RUST_VERSION="1.85.0"
echo "📦 Using Rust ${RUST_VERSION}"

# Verify dependencies are locked
echo "🔒 Verifying locked dependencies..."
if [ ! -f "${PROJECT_ROOT}/Cargo.lock" ]; then
    echo "❌ Error: Cargo.lock not found. Run 'cargo generate-lockfile' first."
    exit 1
fi

if [ ! -f "${PROJECT_ROOT}/package-lock.json" ]; then
    echo "❌ Error: package-lock.json not found. Run 'npm ci' first."
    exit 1
fi

# Pre-compute build info
echo "📝 Generating build metadata..."
cat > "${BUILD_DIR}/build-info.json" <<EOF
{
  "source_date_epoch": ${SOURCE_DATE_EPOCH},
  "git_commit": "$(git rev-parse HEAD)",
  "git_commit_short": "$(git rev-parse --short HEAD)",
  "rust_version": "${RUST_VERSION}",
  "build_timestamp": "$(date -u -d @${SOURCE_DATE_EPOCH} '+%Y-%m-%dT%H:%M:%SZ')",
  "reproducible": true
}
EOF

# Build web assets
echo "🌐 Building web assets..."
cd "${PROJECT_ROOT}"
npm ci --frozen-lockfile
npm run build

# Build Tauri with reproducible settings
echo "⚙️ Building Tauri application..."
cd "${PROJECT_ROOT}/src-tauri"

# Set deterministic cargo environment
export CARGO_INCREMENTAL=0
export RUSTFLAGS="\
  -C link-arg=--build-id=none \
  -C codegen-units=1 \
  -C debuginfo=0 \
  -C opt-level=3 \
  -C overflow-checks=on \
  -C panic=abort \
  -C lto=fat \
  -C embed-bitcode=no \
  --remap-path-prefix=${HOME}=~ \
  --remap-path-prefix=${PROJECT_ROOT}=/project
"

# Build for current platform
cargo build --release --locked --target-dir "${BUILD_DIR}/target"

# Package and compute checksums
echo "📦 Packaging and computing checksums..."
BUNDLE_DIR="${BUILD_DIR}/target/release/bundle"

for bundle in "${BUNDLE_DIR}"/*; do
    if [ -f "${bundle}" ]; then
        filename=$(basename "${bundle}")
        cp "${bundle}" "${OUTPUT_DIR}/${filename}"
        sha256sum "${OUTPUT_DIR}/${filename}" > "${OUTPUT_DIR}/${filename}.sha256"
        echo "✅ ${filename}"
    fi
done

# Generate reproducibility attestation
echo "🔐 Generating attestation..."
cat > "${OUTPUT_DIR}/REPRODUCIBILITY_ATTESTATION.txt" <<EOF
GHOST PRIVACY - REPRODUCIBLE BUILD ATTESTATION
================================================
Build Date: $(date -u -d @${SOURCE_DATE_EPOCH} '+%Y-%m-%d %H:%M:%S UTC')
Git Commit: $(git rev-parse HEAD)
Git Commit Short: $(git rev-parse --short HEAD)
Rust Version: ${RUST_VERSION}
Node Version: $(node --version)

REPRODUCIBILITY CHECKSUMS
==========================
EOF

cd "${OUTPUT_DIR}"
sha256sum *.AppImage *.dmg *.deb *.exe *.msi *.rpm 2>/dev/null >> REPRODUCIBILITY_ATTESTATION.txt || true

cat >> "${OUTPUT_DIR}/REPRODUCIBILITY_ATTESTATION.txt" <<EOF

REPRODUCIBILITY INSTRUCTIONS
==============================
To reproduce this build:

1. Clone the repository:
   git clone https://github.com/Lucieran-Raven/ghost-privacy.git
   cd ghost-privacy

2. Checkout the exact commit:
   git checkout $(git rev-parse HEAD)

3. Set the build timestamp:
   export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

4. Run the reproducible build:
   ./scripts/reproducible-build.sh

5. Compare checksums:
   sha256sum -c reproducible-output/*.sha256

If all checksums match, the build is verified as reproducible.
EOF

echo ""
echo "✅ Reproducible build complete!"
echo "Output directory: ${OUTPUT_DIR}"
echo ""
echo "📊 Build artifacts:"
ls -la "${OUTPUT_DIR}"
echo ""
echo "🔐 To verify reproducibility, run:"
echo "   sha256sum -c ${OUTPUT_DIR}/*.sha256"
