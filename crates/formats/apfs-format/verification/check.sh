#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cargo kani --manifest-path "$verification_dir/../Cargo.toml" \
	--harness nxsb_ --harness object_checksum_window_matches_wire_layout \
	--harness object_header_fields_match_wire_layout
