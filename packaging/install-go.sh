#!/bin/sh
set -eu
case "$(uname -m)" in
 x86_64) arch=amd64; hash=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
 aarch64) arch=arm64; hash=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
 *) echo 'Unsupported build architecture' >&2; exit 1 ;;
esac
curl -fsSL --retry 3 "https://go.dev/dl/go1.27.3.linux-$arch.tar.gz" -o /tmp/go.tgz
printf '%s  /tmp/go.tgz\n' "$hash" | sha256sum -c -
tar -C /usr/local -xzf /tmp/go.tgz
rm /tmp/go.tgz
