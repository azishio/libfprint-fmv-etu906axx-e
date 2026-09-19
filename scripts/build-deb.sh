#!/bin/sh
set -eu

source_dir=${1:-.}
output_dir=${2:-dist/deb}
source_dir=$(CDPATH= cd -- "$source_dir" && pwd)
output_parent=$(dirname -- "$output_dir")
mkdir -p "$output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd)
output_dir=$output_parent/$(basename -- "$output_dir")
mkdir -p "$output_dir"

(cd "$source_dir" && dpkg-buildpackage -B -us -uc)

find "$(dirname "$source_dir")" -maxdepth 1 -type f -name 'libfprint-etu906_*.deb' \
	-exec cp -f {} "$output_dir/" \;
