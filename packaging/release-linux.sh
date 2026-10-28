#!/bin/bash
# Build, sign and publish the Linux packages to an APT (reprepro) and an RPM
# (createrepo_c) repository.
#
#   packaging/release-linux.sh [--with-setup] [--sync]
#
#   --with-setup  include the KEEN Setup desktop app (needs Node.js and npm;
#                 adds desktop dependencies to the package)
#   --sync        rsync the RPM repository to RPM_REMOTE afterwards
#
# Environment:
#   SIGNING_KEY    OpenPGP key that signs packages and repository metadata
#   GPG            signing command (default gpg; qubes-gpg-client for split GPG)
#   DEB_REPO       reprepro base directory (with conf/)
#   RPM_REPO_ROOT  RPM repository root (<release>/rpm/<arch>/ beneath it)
#   RPM_REMOTE     rsync destination for --sync
#   TARGETS        build targets (default: debian12 debian13 fedora43 fedora44 ubuntu22.04 ubuntu24.04 ubuntu26.04)
#
# The version comes from VERSION. Nothing is published unless every target
# builds, and each run builds in a fresh staging directory so a stale package
# can never be published.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
with_setup=false sync_repo=false
for arg in "$@"; do
 case "$arg" in
  --with-setup) with_setup=true ;;
  --sync) sync_repo=true ;;
  *) echo 'Usage: packaging/release-linux.sh [--with-setup] [--sync]' >&2; exit 2 ;;
 esac
done
: "${SIGNING_KEY:?Set SIGNING_KEY}" "${DEB_REPO:?Set DEB_REPO}" "${RPM_REPO_ROOT:?Set RPM_REPO_ROOT}"
gpg_command=${GPG:-gpg}
# Write an armoured detached signature of $1 to stdout. qubes-gpg-client
# always writes to stdout; gpg needs --output - to do the same.
sign() {
 if [[ "$(basename -- "$gpg_command")" == qubes-gpg-client* ]]; then
  "$gpg_command" --local-user "$SIGNING_KEY" --batch --armor --detach-sign "$1"
 else
  "$gpg_command" --local-user "$SIGNING_KEY" --batch --armor --detach-sign --output - "$1"
 fi
}
read -r -a targets <<< "${TARGETS:-debian12 debian13 fedora43 fedora44 ubuntu22.04 ubuntu24.04 ubuntu26.04}"
version=$(cat VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid VERSION: $version" >&2; exit 1; }
for command in docker reprepro rpmsign rpm createrepo_c "$gpg_command"; do
 command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
if "$sync_repo"; then
 : "${RPM_REMOTE:?Set RPM_REMOTE for --sync}"
 command -v rsync >/dev/null || { echo 'Missing command: rsync' >&2; exit 1; }
fi
[ -d "$DEB_REPO/conf" ] || { echo "Missing reprepro configuration: $DEB_REPO/conf" >&2; exit 1; }
go test ./internal/buildinfo
# The Docker build copies dist/setup-app when present, so decide explicitly.
rm -rf dist/setup-app
if "$with_setup"; then
 case "$(uname -m)" in x86_64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) echo 'Unsupported architecture' >&2; exit 1 ;; esac
 npm ci --prefix onboarding
 npm test --prefix onboarding
 SETUP_PLATFORM=linux SETUP_ARCH="$arch" npm run package --prefix onboarding
 cp -a "dist/onboarding/KEEN Setup-linux-$arch" dist/setup-app
 cp dist/setup-icons/keen.png dist/setup-app/keen.png
fi
stage=$(mktemp -d "$PWD/.release-output.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
PACKAGE_OUTPUT_ROOT="$stage" sh packaging/build-packages.sh "${targets[@]}"
rm -rf dist/setup-app
shopt -s nullglob
# Validate every output before modifying either repository.
for target in "${targets[@]}"; do
 packages=("$stage/$target/"*"$version"*.deb "$stage/$target/"*"$version"*.rpm)
 [ "${#packages[@]}" -eq 1 ] || { echo "Expected one $version package for $target" >&2; exit 1; }
done
for target in "${targets[@]}"; do
 packages=("$stage/$target/"*.deb "$stage/$target/"*.rpm)
 package=${packages[0]}
 case "$target" in
  debian12) suite=bookworm ;;
  debian13) suite=trixie ;;
  ubuntu22.04) suite=jammy ;;
  ubuntu24.04) suite=noble ;;
  ubuntu26.04) suite=resolute ;;
  fedora*) suite= ;;
  *) echo "No repository mapping for $target" >&2; exit 1 ;;
 esac
 if [ -n "$suite" ]; then
  sign "$package" > "$package.asc"
  reprepro -b "$DEB_REPO" includedeb "$suite" "$package"
  continue
 fi
 release=${target#fedora}
 rpmsign --define "_gpg_name $SIGNING_KEY" --addsign "$package"
 arch=$(rpm -qp --qf '%{ARCH}' "$package")
 case "$arch" in x86_64|aarch64) ;; *) echo "Unexpected RPM architecture: $arch" >&2; exit 1 ;; esac
 rpm_repo="$RPM_REPO_ROOT/$release/rpm/$arch"
 mkdir -p "$rpm_repo"
 cp -- "$package" "$rpm_repo/"
 createrepo_c "$rpm_repo"
 # Replace the detached metadata signature only after signing succeeds.
 signature=$(mktemp "$stage/repomd.XXXXXX")
 sign "$rpm_repo/repodata/repomd.xml" > "$signature"
 mv -- "$signature" "$rpm_repo/repodata/repomd.xml.asc"
 chmod 644 "$rpm_repo/repodata/repomd.xml.asc"
done
mkdir -p dist/packages
cp -a "$stage/." dist/packages/
if "$sync_repo"; then
 rsync -aHPvz --exclude=.git --delete "$RPM_REPO_ROOT/" "$RPM_REMOTE/"
fi
printf 'Released %s. Signed packages are in dist/packages/.\n' "$version"
