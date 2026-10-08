#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
output_root=${PACKAGE_OUTPUT_ROOT:-dist/packages}
for target in "${@:-all}"; do
 case "$target" in
 all) sh packaging/build-packages.sh debian12 debian13 fedora43 fedora44 ;;
 debian12|debian13) release=${target#debian}; docker build --build-arg RELEASE="$release" -f packaging/Dockerfile.debian --output "type=local,dest=$output_root/$target" . ;;
 fedora43|fedora44) release=${target#fedora}; docker build --build-arg RELEASE="$release" -f packaging/Dockerfile.fedora --output "type=local,dest=$output_root/$target" . ;;
 *) echo "Unknown target: $target" >&2; exit 1 ;;
 esac
done
