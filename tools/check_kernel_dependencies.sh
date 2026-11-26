#!/usr/bin/env bash
set -euo pipefail

package=$1
target=$2
shift 2

case "$target" in
  aarch64-unknown-none|x86_64-unknown-none) ;;
  *) printf 'Unsupported kernel target: %s\n' "$target" >&2; exit 2 ;;
esac
case "$package" in
  libapfs-core|apfs-format) expected=$package ;;
  apfs-container) expected=$(printf '%s\n' apfs-container apfs-format libapfs-core) ;;
  apfs-reader) expected=$(printf '%s\n' apfs-container apfs-format apfs-reader libapfs-core) ;;
  *) printf 'Unsupported kernel package: %s\n' "$package" >&2; exit 2 ;;
esac

tree=$(cargo tree --locked -p "$package" --no-default-features --target "$target" \
  -e normal,no-proc-macro --prefix none --format '{p}' "$@")
actual=$(awk '{ print $1 }' <<< "$tree" | LC_ALL=C sort -u)
if [[ "$actual" != "$expected" ]]; then
  printf '%s (%s) has an unexpected kernel dependency graph\n%s\n' \
    "$package" "$target" "$actual" >&2
  exit 1
fi
