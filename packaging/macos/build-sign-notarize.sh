#!/bin/bash
set -euo pipefail
# Run on macOS with Go, Xcode command-line tools and Developer ID identities.
: "${APPLICATION_IDENTITY:?Developer ID Application identity required}"
: "${INSTALLER_IDENTITY:?Developer ID Installer identity required}"
: "${NOTARY_PROFILE:?notarytool keychain profile required}"
[[ $(uname -s) == Darwin ]] || { echo 'Build on macOS' >&2; exit 1; }
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
out="$repo/dist/macos"
mkdir -p "$out" "$work/root/usr/local/libexec" "$work/root/Library/LaunchDaemons" "$work/scripts"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -o "$work/keen-posture-$arch" ./cmd/keen-posture
done
lipo -create "$work/keen-posture-amd64" "$work/keen-posture-arm64" -output "$work/root/usr/local/libexec/keen-posture"
codesign --force --options runtime --timestamp --sign "$APPLICATION_IDENTITY" "$work/root/usr/local/libexec/keen-posture"
codesign --verify --strict --verbose=2 "$work/root/usr/local/libexec/keen-posture"
cp packaging/macos/net.keen.posture.plist "$work/root/Library/LaunchDaemons/"
cp packaging/macos/postinstall "$work/scripts/postinstall"
chmod 755 "$work/scripts/postinstall"
chmod 644 "$work/root/Library/LaunchDaemons/net.keen.posture.plist"
pkgbuild --root "$work/root" --scripts "$work/scripts" --identifier net.keen.posture --version 0.1.7 --install-location / "$work/unsigned.pkg"
productsign --sign "$INSTALLER_IDENTITY" --timestamp "$work/unsigned.pkg" "$out/keen-posture-0.1.7.pkg"
xcrun notarytool submit "$out/keen-posture-0.1.7.pkg" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json > "$work/notary.json"
[[ $(plutil -extract status raw -o - "$work/notary.json") == Accepted ]] || { cat "$work/notary.json"; exit 1; }
xcrun stapler staple "$out/keen-posture-0.1.7.pkg"
xcrun stapler validate "$out/keen-posture-0.1.7.pkg"
pkgutil --check-signature "$out/keen-posture-0.1.7.pkg"
spctl --assess --type install --verbose=2 "$out/keen-posture-0.1.7.pkg"
echo "$out/keen-posture-0.1.7.pkg"
