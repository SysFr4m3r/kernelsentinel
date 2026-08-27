#!/bin/bash
# Noise: an ordinary compile.
#   ks-expect: silence
#   ks-run: host
#
# Exec-heavy by design -- rustc, ld, build scripts, hundreds of short-lived
# processes. A correlation engine that mistakes a build for activity worth
# reporting would be unusable on any developer machine or CI runner.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v cargo >/dev/null || { echo "cargo required" >&2; exit 90; }
cd "$REPO"
# Touch a source file so this is a real compile, not a cache hit.
touch src/lib.rs
cargo build --quiet 2>/dev/null || true
echo "[noise] developer_build complete"
