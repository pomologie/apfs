#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash "$verification_dir/check-bootstrap-properties.sh" |
	python3 -B "$verification_dir/bootstrap_wire_oracle.py"
