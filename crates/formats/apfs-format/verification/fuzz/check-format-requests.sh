#!/usr/bin/env bash
set -euo pipefail

fuzz_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/apfs-format-requests.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
corpus="$scratch/corpus"
mkdir "$corpus"

# Only scalar selectors enter the corpus. Fixture bytes are compiled into the harness.
python3 -B - "$corpus" <<'PY'
from pathlib import Path
from struct import pack
import sys

corpus = Path(sys.argv[1])
block_count = 16_384
max_u64 = (1 << 64) - 1
windows = [(0, fixture, length) for fixture in range(7) for length in (0, 27, 28, 31, 32, 33, 4096)]
ranges = [(1, start, count) for start, count in (
    (0, 0), (0, block_count), (block_count, 0), (block_count, 1), (max_u64, 1), (1, max_u64),
)]
projected = [(2, start, count) for start, count in ((0, 1), (block_count - 1, 1), (block_count, 0))]
for i, record in enumerate(windows + ranges + projected):
    (corpus / f"request-{i:02}").write_bytes(pack("<BQQ", *record))
PY

toolchain=nightly-2026-11-04
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
rustc --version
cargo fuzz --version
cargo tree --locked --manifest-path "$fuzz_dir/Cargo.toml" --depth 1 --prefix none
target=$(rustc --print host-tuple)
export ASAN_OPTIONS=halt_on_error=1:abort_on_error=1
printf 'APFS format fuzz AddressSanitizer %s seed 7 runs 20000 max-request-bytes 17\n' "$toolchain"
cargo fuzz build --fuzz-dir "$fuzz_dir" --target-dir "$scratch/target" --target "$target" \
	--sanitizer address --no-default-features format-requests
"$scratch/target/$target/release/format-requests" "$corpus" \
	-seed=7 -runs=20000 -max_len=17 "-artifact_prefix=$scratch/"
printf 'APFS format requests fuzz completed\n'
