#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	printf 'Usage: %s PATH_TO_TLA2TOOLS_JAR\n' "$0" >&2
	exit 2
fi

jar_dir=$(cd "$(dirname -- "$1")" && pwd)
jar="$jar_dir/$(basename -- "$1")"
expected_sha256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jar_digest=$(LC_ALL=C shasum -a 256 -- "$jar")
if [[ ${jar_digest%% *} != "$expected_sha256" ]]; then
	printf 'Expected the official TLA+ Tools v1.7.4 jar at %s\n' "$jar" >&2
	exit 2
fi

model_dir=$(cd "$(dirname -- "$0")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/apfs-checkpoint-tlc.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
cd "$scratch"
cp "$model_dir/CheckpointSelection.tla" "$model_dir/CheckpointSelection.cfg" .
java -Xmx512m -XX:+UseParallelGC -Djava.io.tmpdir="$scratch" -cp "$jar" \
	tlc2.TLC -workers 1 -seed 0 -fp 0 CheckpointSelection
