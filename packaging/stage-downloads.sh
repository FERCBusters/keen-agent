#!/bin/bash
# Arrange release artefacts in the published download layout, with SHA-256
# sums and detached OpenPGP signatures, ready to copy to the download host.
#
#   packaging/stage-downloads.sh [ARTEFACT...]
#
# With no arguments it collects the artefacts the build scripts leave in
# dist/: Windows MSIs, the macOS package and the Linux packages. The result is
# dist/downloads/keen-agent/<version>/ plus a `latest` link to it.
#
# Environment: SIGNING_KEY (OpenPGP key ID or fingerprint, required unless
# UNSIGNED=1) and GPG (the signing command; default gpg, or qubes-gpg-client).
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
version=$(cat VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid VERSION: $version" >&2; exit 1; }
gpg_command=${GPG:-gpg}
unsigned=${UNSIGNED:-0}
# Write an armoured detached signature of $1 to stdout. qubes-gpg-client
# always writes to stdout; gpg needs --output - to do the same.
sign() {
 if [[ "$(basename -- "$gpg_command")" == qubes-gpg-client* ]]; then
  "$gpg_command" --local-user "$SIGNING_KEY" --batch --armor --detach-sign "$1"
 else
  "$gpg_command" --local-user "$SIGNING_KEY" --batch --armor --detach-sign --output - "$1"
 fi
}
if [[ "$unsigned" != 1 ]]; then
 : "${SIGNING_KEY:?Set SIGNING_KEY to the release key, or UNSIGNED=1 for a test layout}"
 command -v "$gpg_command" >/dev/null || { echo "Missing signing command: $gpg_command" >&2; exit 1; }
fi
shopt -s nullglob
artefacts=("$@")
if [[ ${#artefacts[@]} -eq 0 ]]; then
 artefacts=(dist/windows-*/keen-posture-"$version"-windows-*.msi dist/macos/keen-posture-"$version"-macos-universal.pkg dist/packages/*/*.deb dist/packages/*/*.rpm)
fi
[[ ${#artefacts[@]} -gt 0 ]] || { echo "No release artefacts found for $version" >&2; exit 1; }
root=dist/downloads/keen-agent
target="$root/$version"
rm -rf -- "$target"
mkdir -p "$target"
for file in "${artefacts[@]}"; do
 name=$(basename -- "$file")
 case "$name" in
  *"$version"*) ;;
  *) echo "Refusing $name: its name does not carry version $version" >&2; exit 1 ;;
 esac
 [[ ! -e "$target/$name" ]] || { echo "Duplicate artefact name: $name" >&2; exit 1; }
 cp -- "$file" "$target/$name"
done
(
 cd "$target"
 sha256sum -- * > SHA256SUMS
 if [[ "$unsigned" != 1 ]]; then
  for file in *; do
   [[ "$file" == *.asc ]] && continue
   sign "$file" > "$file.asc"
  done
 fi
)
ln -sfn "$version" "$root/latest"
printf 'Staged %s:\n' "$target"
ls -1 "$target"
