#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/apfs-native-checkpoint-compare.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT

status=0
bash "$verification_dir/check-native-checkpoints.sh" > "$scratch/replay.log" 2>&1 || status=$?
cat "$scratch/replay.log"
test "$status" -eq 0
python3 -B "$verification_dir/compare_native_checkpoints.py" "$scratch/replay.log"
printf 'APFS checkpoint differential completed\n'
