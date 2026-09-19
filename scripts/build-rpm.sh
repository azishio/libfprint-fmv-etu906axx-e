#!/bin/sh
set -eu

source_dir=${1:-.}
output_dir=${2:-dist/rpm}
source_dir=$(CDPATH= cd -- "$source_dir" && pwd)
output_parent=$(dirname -- "$output_dir")
mkdir -p "$output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd)
output_dir=$output_parent/$(basename -- "$output_dir")
mkdir -p "$output_dir"

topdir=$(mktemp -d "${TMPDIR:-/tmp}/libfprint-etu906-rpm.XXXXXX")
trap 'rm -rf "$topdir"' EXIT HUP INT TERM
mkdir -p "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SOURCES" "$topdir/SPECS" "$topdir/SRPMS"

version=$(awk '/^Version:/{print $2}' "$source_dir/packaging/libfprint-etu906.spec")
tarball="$topdir/SOURCES/libfprint-etu906-$version.tar.gz"
tar --exclude-vcs --exclude='./_build*' --exclude='./obj-*' --exclude='./dist' --exclude='./redhat-linux-build' -czf "$tarball" \
	-C "$source_dir" --transform="s,^\.,libfprint-etu906-$version," .
cp "$source_dir/packaging/libfprint-etu906.spec" "$topdir/SPECS/"

rpmbuild --define "_topdir $topdir" -bb "$topdir/SPECS/libfprint-etu906.spec"
find "$topdir/RPMS" -type f -name 'libfprint-etu906-*.rpm' \
	! -name '*-debuginfo-*' ! -name '*-debugsource-*' -exec cp -f {} "$output_dir/" \;
