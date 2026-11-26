#!/usr/bin/env bash
set -euo pipefail

model_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
jar=${TLA2TOOLS_JAR:?set TLA2TOOLS_JAR to the pinned TLA+ Tools jar}
scratch=$(mktemp -d "${TMPDIR:-/tmp}/apfs-checkpoint-witness.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT

printf 'APFS TLC baseline\n'
bash "$model_dir/check.sh" "$jar"

cp "$model_dir/check.sh" "$model_dir/CheckpointSelection.cfg" "$scratch/"
python3 -B - "$model_dir/CheckpointSelection.tla" "$scratch/CheckpointSelection.tla" <<'PY'
from pathlib import Path
import sys

original, witness = map(Path, sys.argv[1:])
source = original.read_text(encoding="utf-8")
selected = 'ELSE CASE candidate.map = "complete" ->'
wrong_selection = r'''ELSE CASE (candidate.map = "complete"
                       \/ (candidate.map = "missing" /\ xid = 2 /\ requested = NoXid
                           /\ \E s \in pending : ring[s].xid < xid /\ ring[s].map = "complete")) ->'''
if source.count(selected) != 1:
    raise SystemExit("Expected one checkpoint selection branch for the TLC witness")
witness.write_text(source.replace(selected, wrong_selection), encoding="utf-8")
PY

printf 'APFS TLC negative witness\n'
status=0
bash "$scratch/check.sh" "$jar" > "$scratch/witness.log" 2>&1 || status=$?
cat "$scratch/witness.log"
printf 'APFS TLC witness exit code: %s\n' "$status"

# TLC reports code 12 for an invariant violation outside the initial state.
test "$status" -eq 12
test "$(grep -Fxc 'Error: Invariant SelectionMatchesEvidence is violated.' "$scratch/witness.log")" -eq 1
