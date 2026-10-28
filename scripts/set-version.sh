#!/bin/sh
# Set the release version everywhere it is recorded. VERSION is the source;
# the Go constant and the setup app's package files must match it, which
# `go test ./internal/buildinfo` checks.
set -eu
cd "$(dirname "$0")/.."
version=${1:?usage: scripts/set-version.sh MAJOR.MINOR.PATCH}
case "$version" in
 *[!0-9.]*|.*|*.|*..*) echo "Invalid version: $version" >&2; exit 2 ;;
esac
[ "$(printf '%s' "$version" | tr -cd . | wc -c)" -eq 2 ] || { echo "Invalid version: $version" >&2; exit 2; }
printf '%s\n' "$version" > VERSION
sed -i.bak "s/^const Version = \".*\"$/const Version = \"$version\"/" internal/buildinfo/buildinfo.go && rm -f internal/buildinfo/buildinfo.go.bak
npm version --no-git-tag-version --allow-same-version "$version" --prefix onboarding >/dev/null
go test ./internal/buildinfo
echo "Version set to $version"
