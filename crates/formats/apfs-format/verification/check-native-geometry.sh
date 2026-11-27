#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
toolchain=1.99.1
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
test_name=report_retained_native_geometry_and_mapping_extents
test_args=(--exact --nocapture --test-threads=1)
case "$#:${1:-}" in
	0:) ;;
	1:--size-matrix)
		test_name=report_retained_native_block_size_matrix
		test_args+=(--ignored)
		export APFS_NATIVE_GEOMETRY_FIXTURES="$verification_dir/../../../container/apfs-container/tests/fixtures/native-bootstrap-sizes"
		;;
	*) printf 'Usage: %s [--size-matrix]\n' "$0" >&2; exit 2 ;;
esac

rustc --version
cargo test --locked --manifest-path "$verification_dir/../Cargo.toml" \
	--no-default-features --test native_geometry "$test_name" -- \
	"${test_args[@]}" |
	python3 -B "$verification_dir/native_geometry_oracle.py" "$@"
printf 'APFS native geometry differential completed\n'
