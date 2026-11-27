#!/usr/bin/env bash
set -euo pipefail

fuzz_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/apfs-format-requests.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
corpus="$scratch/corpus"
mkdir "$corpus"

# Only scalar selectors enter the corpus. Fixture bytes are compiled into the harness.
python3 -B - "$corpus" "$fuzz_dir" <<'PY'
from hashlib import sha256
from pathlib import Path
from struct import pack
import sys

corpus = Path(sys.argv[1])
crate = Path(sys.argv[2]).resolve().parents[1]
format_fixtures = crate / "tests" / "fixtures"
size_fixtures = crate.parents[1] / "container" / "apfs-container" / "tests" / "fixtures" / "native-bootstrap-sizes"
widths = (4096, 8192, 16384, 32768, 65536)
objects = [format_fixtures / name for name in (
    "native-block-0.bin", "native-block-1.bin", "native-block-2.bin", "native-block-3.bin", "native-block-4.bin",
    "sonoma-populated-omap-container.bin", "sonoma-populated-omap-volume.bin",
)] + [size_fixtures / f"native-block-zero-{width}.bin" for width in widths]
fixture_digest = sha256()
for source in objects:
    fixture_digest.update(sha256(source.read_bytes()).digest())
max_u64 = (1 << 64) - 1
windows = [(0, fixture, length) for fixture, source in enumerate(objects)
           for size in (source.stat().st_size,) for length in (0, 27, 28, 31, 32, 33, size - 1, size)]
queries = []
for fixture, (width, extent) in enumerate(((4096, 64 << 20), *((width, 128 << 20) for width in widths))):
    selector = fixture * 4
    block_count = extent // width
    queries.extend((selector + 1, start, count) for start, count in (
        (0, 0), (0, block_count), (block_count, 0), (block_count, 1), (max_u64, 1), (1, max_u64),
    ))
    queries.extend((selector + 2, start, count) for start, count in ((0, 1), (block_count - 1, 1), (block_count, 0)))
    queries.extend((selector + 3, source, mode)
                   for source in (0, extent - 1, extent, extent + 1, max_u64) for mode in (0, 1))
    print(f"APFS format fuzz geometry-seeds {fixture} {width} {block_count} 6 3 10")
seed_digest = sha256()
for index, record in enumerate(windows + queries):
    request = pack("<BQQ", *record)
    seed_digest.update(request)
    (corpus / f"request-{index:03}").write_bytes(request)
print(f"APFS format fuzz input {len(objects)} {len(windows) + len(queries)} {fixture_digest.hexdigest()} {seed_digest.hexdigest()}")
PY

toolchain=nightly-2026-11-04
compiler=$(rustup which --toolchain "$toolchain" rustc)
toolchain_bin=$(dirname -- "$compiler")
export PATH="$toolchain_bin:$PATH" RUSTC="$compiler"
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
