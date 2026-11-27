#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
APFS_CHECKPOINT_DECISION_OUTCOMES=1 bash "$verification_dir/check-checkpoint-decisions.sh" |
	python3 -B "$verification_dir/checkpoint_decision_oracle.py"
