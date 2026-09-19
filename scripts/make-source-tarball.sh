#!/bin/sh
set -eu

source_dir=${1:-.}
output=${2:-libfprint-etu906-0.1.0.tar.gz}
source_dir=$(CDPATH= cd -- "$source_dir" && pwd)
version=$(sed -n '1s/.*(\([^-]*\)-.*/\1/p' "$source_dir/debian/changelog")
prefix=libfprint-etu906-$version/
tar_prefix=${prefix%/}
output_dir=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)
output=$(printf '%s/%s' "$output_dir" "$(basename -- "$output")")
temporary_output=$(mktemp "${TMPDIR:-/tmp}/libfprint-etu906-source.XXXXXX")
trap 'rm -f "$temporary_output"' EXIT HUP INT TERM

if git -C "$source_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	git -C "$source_dir" archive --format=tar.gz --prefix="$prefix" HEAD >"$temporary_output"
else
	tar --exclude-vcs --exclude='./.git' --exclude='./_build*' --exclude='./obj-*' --exclude='./dist' --exclude='./redhat-linux-build' -czf "$temporary_output" \
		-C "$source_dir" --transform="s,^\\.,$tar_prefix," .
fi

mv -f "$temporary_output" "$output"
trap - EXIT HUP INT TERM
